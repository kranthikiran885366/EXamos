#![forbid(unsafe_code)]
//! Privileged Rust Security Daemon Core (`sppio-securityd`)
//!
//! Enforces:
//! - Tamper-triggered RAM & FDE key zeroization (`zeroize::Zeroize`)
//! - Linux IMA runtime measurement PCR-10 chain replay (Keylime-compatible)
//! - IOMMU / Thunderbolt / PCIe DMA attack surface validation
//! - Air-gapped operation with ML-DSA-65 signed offline bundles & hardware token presence

pub mod canary_tripwire;
pub mod proximity_shield;
pub mod tpm_log_chain;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sppio_behavioral_ai::{
    BehavioralAssessment, KeystrokeSample, ThreatVerdict, WaylandSurfaceTelemetry,
    assess_keystroke_window, assess_overlay_telemetry,
};
use sppio_pqc::{AirGappedBundle, PqcError};
use std::io::Read;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default location for the daemon's ephemeral key material.
pub const DEFAULT_KEY_DIR: &str = "/run/examos/keys";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TamperTrigger {
    ChassisIntrusion,
    LidTamper,
    AttestationFailure,
    UnexpectedShutdown,
    BpfLsmViolation,
    BadUsbInjection,
    DmaUnauthorizedDevice,
    CanaryTripwire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroizationReceipt {
    pub triggered_by: TamperTrigger,
    pub fde_key_scrubbed: bool,
    pub session_key_scrubbed: bool,
    pub pqc_secret_scrubbed: bool,
    pub lockdown_engaged: bool,
    /// I/O or process failures encountered while scrubbing on-disk key material.
    /// A non-empty list means the in-memory keys were zeroized but the
    /// on-disk copy could not be fully erased; the daemon must stay locked down.
    #[serde(default)]
    pub wipe_errors: Vec<String>,
}

/// Memory-safe key vault that guarantees cryptographic zeroization on drop or tamper.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VolatileKeyVault {
    fde_master_key: [u8; 32],
    exam_session_key: [u8; 32],
    pqc_ephemeral_secret: [u8; 32],
    #[zeroize(skip)]
    key_dir: String,
    #[zeroize(skip)]
    zeroized: bool,
    #[zeroize(skip)]
    lockdown_engaged: bool,
}

impl VolatileKeyVault {
    pub fn initialize(fde: [u8; 32], session: [u8; 32], pqc: [u8; 32]) -> Self {
        Self {
            fde_master_key: fde,
            exam_session_key: session,
            pqc_ephemeral_secret: pqc,
            key_dir: DEFAULT_KEY_DIR.to_string(),
            zeroized: false,
            lockdown_engaged: false,
        }
    }

    /// Overrides the runtime directory used when wiping on-disk key material.
    pub fn with_key_dir(mut self, dir: &str) -> Self {
        self.key_dir = dir.to_string();
        self
    }

    pub fn is_zeroized(&self) -> bool {
        self.zeroized
    }

    pub fn is_locked_down(&self) -> bool {
        self.lockdown_engaged
    }

    /// Loads the three key files, requiring each to contain exactly 32 bytes.
    /// Missing or truncated key material is an error rather than a silent
    /// all-zero fallback, which would make DMA posture checks meaningless.
    pub fn try_load_from_runtime_dir(dir: &str) -> Result<Self, String> {
        let read_key = |name: &str| -> Result<[u8; 32], String> {
            let path = Path::new(dir).join(name);
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("cannot read key material {}: {e}", path.display()))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "key material {} must be exactly 32 bytes, found {}",
                    path.display(),
                    bytes.len()
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(key)
        };
        let vault = Self::initialize(
            read_key("fde.key")?,
            read_key("session.key")?,
            read_key("pqc.key")?,
        )
        .with_key_dir(dir);
        Ok(vault)
    }

    /// Generates an ephemeral vault from the operating system CSPRNG. Used only
    /// when the caller explicitly opts into ephemeral keys (self-test / dry run).
    pub fn from_os_random() -> Result<Self, String> {
        let mut random = [0u8; 96];
        let mut source = std::fs::File::open("/dev/urandom")
            .map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
        source
            .read_exact(&mut random)
            .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;

        let mut fde = [0u8; 32];
        let mut session = [0u8; 32];
        let mut pqc = [0u8; 32];
        fde.copy_from_slice(&random[0..32]);
        session.copy_from_slice(&random[32..64]);
        pqc.copy_from_slice(&random[64..96]);
        random.zeroize();
        Ok(Self::initialize(fde, session, pqc))
    }

    /// Immediately scrubs all sensitive key material in RAM, then best-effort
    /// erases the on-disk copies in the configured runtime directory. I/O
    /// failures are recorded in the receipt and do not silently pass.
    pub fn tamper_zeroize(&mut self, trigger: TamperTrigger) -> ZeroizationReceipt {
        self.fde_master_key.zeroize();
        self.exam_session_key.zeroize();
        self.pqc_ephemeral_secret.zeroize();
        self.zeroized = true;
        self.lockdown_engaged = true;

        let mut wipe_errors = Vec::new();
        let key_dir = Path::new(&self.key_dir);
        if key_dir.exists() {
            for name in ["fde.key", "session.key", "pqc.key"] {
                let path = key_dir.join(name);
                if !path.exists() {
                    continue;
                }
                if let Err(error) = std::fs::write(&path, [0u8; 32]) {
                    wipe_errors.push(format!("failed to overwrite {}: {error}", path.display()));
                    continue;
                }
                if let Err(error) = std::fs::remove_file(&path) {
                    wipe_errors.push(format!("failed to unlink {}: {error}", path.display()));
                }
            }
        } else {
            wipe_errors.push(format!(
                "runtime key directory {} is unavailable",
                key_dir.display()
            ));
        }

        if let Err(error) = std::fs::write("/proc/sys/vm/drop_caches", "3\n") {
            wipe_errors.push(format!("failed to drop kernel page cache: {error}"));
        }
        if Path::new("/dev/mapper/examos-root").exists() {
            match std::process::Command::new("cryptsetup")
                .args(["luksSuspend", "examos-root"])
                .output()
            {
                Ok(output) if output.status.success() => {}
                Ok(output) => wipe_errors.push(format!(
                    "cryptsetup luksSuspend failed with status {}",
                    output.status
                )),
                Err(error) => wipe_errors.push(format!("cannot execute cryptsetup: {error}")),
            }
        }

        ZeroizationReceipt {
            triggered_by: trigger,
            fde_key_scrubbed: self.fde_master_key == [0u8; 32],
            session_key_scrubbed: self.exam_session_key == [0u8; 32],
            pqc_secret_scrubbed: self.pqc_ephemeral_secret == [0u8; 32],
            lockdown_engaged: self.lockdown_engaged,
            wipe_errors,
        }
    }
}

/// Parsed entry from `/sys/kernel/security/ima/ascii_runtime_measurements`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImaMeasurementEntry {
    pub pcr_index: u32,
    pub template_hash_hex: String,
    pub template_name: String,
    pub file_digest_hex: String,
    pub file_path: String,
}

/// Recomputes the `ima-ng` template hash from the measured file digest and path.
///
/// Linux hashes each template field as `LE32(field_len) || field_bytes` in the
/// canonical format. Non-canonical kernels use the host byte order, so both
/// endiannesses are accepted. `ima-sig` adds a signature field that is not
/// present in the ASCII log, so its template hash cannot be reconstructed here.
fn verify_ima_ng_template_hash(
    template_name: &str,
    file_digest_hex: &str,
    file_path: &str,
    template_hash_hex: &str,
) -> Result<(), String> {
    if template_name != "ima-ng" {
        return Ok(());
    }
    let digest = hex::decode(file_digest_hex)
        .map_err(|_| format!("invalid file digest on {file_path}"))?;
    let path = file_path.as_bytes();

    for little_endian in [true, false] {
        let mut hasher = Sha256::new();
        if little_endian {
            hasher.update((digest.len() as u32).to_le_bytes());
            hasher.update(&digest);
            hasher.update((path.len() as u32).to_le_bytes());
            hasher.update(path);
        } else {
            hasher.update((digest.len() as u32).to_be_bytes());
            hasher.update(&digest);
            hasher.update((path.len() as u32).to_be_bytes());
            hasher.update(path);
        }
        if hex::encode(hasher.finalize()).eq_ignore_ascii_case(template_hash_hex) {
            return Ok(());
        }
    }

    Err(format!(
        "IMA template hash mismatch for {file_path} ({template_name})"
    ))
}

/// Replays the IMA PCR-10 extension chain.
///
/// When `allowlist_sha256` is `Some`, every measured path must be present and
/// its digest must match, so an unlisted binary fails closed. `None` is used by
/// the replay-only CLI path where the caller supplies the expected PCR value.
pub fn replay_ima_pcr10(
    ascii_log: &str,
    allowlist_sha256: Option<&[(&str, &str)]>,
) -> Result<(Vec<ImaMeasurementEntry>, String), String> {
    let mut pcr10 = [0u8; 32];
    let mut entries = Vec::new();

    for (line_no, raw) in ascii_log.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Err(format!("malformed IMA line {}", line_no + 1));
        }
        let pcr_index: u32 = parts[0]
            .parse()
            .map_err(|_| format!("invalid PCR index on line {}", line_no + 1))?;
        let template_hash_bytes = hex::decode(parts[1])
            .map_err(|_| format!("invalid template hash hex on line {}", line_no + 1))?;
        if template_hash_bytes.len() != 32 {
            return Err(format!("non-SHA256 template hash on line {}", line_no + 1));
        }
        let template_name = parts[2].to_string();
        let file_digest_part = parts[3]
            .strip_prefix("sha256:")
            .or_else(|| parts[3].strip_prefix("sha1:"))
            .unwrap_or(parts[3])
            .to_string();
        let file_path = parts[4].to_string();

        if let Some(allowlist) = allowlist_sha256 {
            match allowlist.iter().find(|(path, _)| *path == file_path) {
                Some((_, expected_digest)) => {
                    if !file_digest_part.eq_ignore_ascii_case(expected_digest) {
                        return Err(format!(
                            "IMA allowlist mismatch for {}: expected {}, got {}",
                            file_path, expected_digest, file_digest_part
                        ));
                    }
                }
                None => {
                    return Err(format!(
                        "IMA measured unlisted path {} on line {}",
                        file_path,
                        line_no + 1
                    ));
                }
            }
        }

        verify_ima_ng_template_hash(
            &template_name,
            &file_digest_part,
            &file_path,
            parts[1],
        )?;

        if pcr_index == 10 {
            let mut hasher = Sha256::new();
            hasher.update(pcr10);
            hasher.update(&template_hash_bytes);
            pcr10.copy_from_slice(&hasher.finalize());
        }

        entries.push(ImaMeasurementEntry {
            pcr_index,
            template_hash_hex: parts[1].to_string(),
            template_name,
            file_digest_hex: file_digest_part,
            file_path,
        });
    }

    Ok((entries, hex::encode(pcr10)))
}

/// Replays Linux IMA PCR-10 extension chain and verifies every measured file against an allowlist.
pub fn verify_ima_measurements(
    ascii_log: &str,
    expected_pcr10_hex: &str,
    allowlist_sha256: &[(&str, &str)],
) -> Result<Vec<ImaMeasurementEntry>, String> {
    let (entries, replayed_hex) = replay_ima_pcr10(ascii_log, Some(allowlist_sha256))?;
    if !replayed_hex.eq_ignore_ascii_case(expected_pcr10_hex) {
        return Err(format!(
            "IMA PCR-10 mismatch: replayed {}, expected {}",
            replayed_hex, expected_pcr10_hex
        ));
    }
    Ok(entries)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmaPosture {
    pub iommu_enabled: bool,
    pub iommu_strict: bool,
    pub thunderbolt_authorized_count: u32,
    pub unapproved_pcie_dma_devices: Vec<String>,
}

pub fn enforce_dma_policy(posture: &DmaPosture, vault: &mut VolatileKeyVault) -> Result<(), ZeroizationReceipt> {
    if !posture.iommu_enabled
        || !posture.iommu_strict
        || posture.thunderbolt_authorized_count > 0
        || !posture.unapproved_pcie_dma_devices.is_empty()
    {
        return Err(vault.tamper_zeroize(TamperTrigger::DmaUnauthorizedDevice));
    }
    Ok(())
}

/// Evaluates behavioral telemetry and triggers RAM zeroization if a critical attack is detected.
pub fn evaluate_behavioral_and_protect(
    keys: &[KeystrokeSample],
    overlay: &WaylandSurfaceTelemetry,
    vault: &mut VolatileKeyVault,
) -> (BehavioralAssessment, BehavioralAssessment, Option<ZeroizationReceipt>) {
    let key_res = assess_keystroke_window(keys);
    let ov_res = assess_overlay_telemetry(overlay);
    let receipt = if key_res.verdict == ThreatVerdict::CriticalAttack {
        Some(vault.tamper_zeroize(TamperTrigger::BadUsbInjection))
    } else if ov_res.verdict == ThreatVerdict::CriticalAttack {
        Some(vault.tamper_zeroize(TamperTrigger::BpfLsmViolation))
    } else {
        None
    };
    (key_res, ov_res, receipt)
}

/// Verifies an air-gapped bundle using ML-DSA-65 without any network connectivity.
pub fn verify_airgapped_update(
    bundle: &AirGappedBundle,
    authority_vk: &[u8],
    smartcard_pin_verified: bool,
) -> Result<Vec<u8>, String> {
    if !smartcard_pin_verified {
        return Err("Air-gapped update requires verified PKCS#11 hardware token / smartcard auth".to_string());
    }
    bundle
        .verify_offline(authority_vk)
        .map_err(|e: PqcError| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sppio_pqc::DsaKeypair;

    #[test]
    fn tamper_zeroization_scrubs_all_keys_and_engages_lockdown() {
        let mut vault = VolatileKeyVault::initialize([0xAA; 32], [0xBB; 32], [0xCC; 32]);
        assert!(!vault.is_zeroized());
        let receipt = vault.tamper_zeroize(TamperTrigger::ChassisIntrusion);
        assert!(receipt.fde_key_scrubbed);
        assert!(receipt.session_key_scrubbed);
        assert!(receipt.pqc_secret_scrubbed);
        assert!(receipt.lockdown_engaged);
        assert!(vault.is_zeroized());
        assert!(vault.is_locked_down());
    }

    #[test]
    fn keylime_ima_pcr10_replay_verifies_and_rejects_tamper() {
        let file_digest = Sha256::digest(b"examos-kiosk-bin");
        let path = "/usr/local/bin/examos-kiosk";
        let mut template = Sha256::new();
        template.update((file_digest.len() as u32).to_le_bytes());
        template.update(file_digest);
        template.update((path.len() as u32).to_le_bytes());
        template.update(path.as_bytes());
        let t1 = hex::encode(template.finalize());
        let f1 = hex::encode(file_digest);
        let line = format!("10 {t1} ima-ng sha256:{f1} {path}\n");

        let mut pcr10 = [0u8; 32];
        let mut h = Sha256::new();
        h.update(pcr10);
        h.update(hex::decode(&t1).unwrap());
        pcr10.copy_from_slice(&h.finalize());
        let expected_pcr = hex::encode(pcr10);

        let allowlist = [(path, f1.as_str())];
        let parsed = verify_ima_measurements(&line, &expected_pcr, &allowlist).expect("valid IMA");
        assert_eq!(parsed.len(), 1);

        let bad_allowlist = [(path, "0000000000000000000000000000000000000000000000000000000000000000")];
        assert!(verify_ima_measurements(&line, &expected_pcr, &bad_allowlist).is_err());
    }

    #[test]
    fn ima_replay_rejects_unlisted_paths_and_bad_template_hashes() {
        let digest = Sha256::digest(b"unlisted-binary");
        let digest_hex = hex::encode(digest);
        let path = "/usr/local/bin/unlisted";
        let mut template = Sha256::new();
        template.update((digest.len() as u32).to_le_bytes());
        template.update(digest);
        template.update((path.len() as u32).to_le_bytes());
        template.update(path.as_bytes());
        let template_hash = hex::encode(template.finalize());
        let line = format!("10 {template_hash} ima-ng sha256:{digest_hex} {path}\n");
        let expected_pcr = "00".repeat(32);

        // The path is not in the allowlist: fail closed.
        let allowlist = [("/usr/local/bin/examos-kiosk", "00")];
        assert!(verify_ima_measurements(&line, &expected_pcr, &allowlist).is_err());

        // The path and digest are trusted, but the template hash is wrong.
        let wrong_template = format!("10 {} ima-ng sha256:{digest_hex} {path}\n", "11".repeat(32));
        assert!(verify_ima_measurements(
            &wrong_template,
            &expected_pcr,
            &[(path, digest_hex.as_str())]
        )
        .is_err());
    }

    #[test]
    fn dma_attack_triggers_immediate_zeroization() {
        let mut vault = VolatileKeyVault::initialize([0x11; 32], [0x22; 32], [0x33; 32]);
        let unsafe_dma = DmaPosture {
            iommu_enabled: true,
            iommu_strict: true,
            thunderbolt_authorized_count: 1,
            unapproved_pcie_dma_devices: vec!["0000:04:00.0".to_string()],
        };
        let err = enforce_dma_policy(&unsafe_dma, &mut vault).unwrap_err();
        assert_eq!(err.triggered_by, TamperTrigger::DmaUnauthorizedDevice);
        assert!(vault.is_zeroized());
    }

    #[test]
    fn airgapped_mode_requires_smartcard_and_mldsa65() {
        let kp = DsaKeypair::generate();
        let bundle = AirGappedBundle::create_signed("airgap-1", "SLOT_B", "2.19.0", b"ROOTFS", &kp);
        assert!(verify_airgapped_update(&bundle, &kp.vk_bytes, false).is_err());
        let ok = verify_airgapped_update(&bundle, &kp.vk_bytes, true).expect("smartcard + ML-DSA-65");
        assert_eq!(ok, b"ROOTFS");
    }
}
