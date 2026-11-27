#![forbid(unsafe_code)]
//! Privileged Rust Security Daemon Core (`sppio-securityd`)
//!
//! Enforces:
//! - Tamper-triggered RAM & FDE key zeroization (`zeroize::Zeroize`)
//! - Linux IMA runtime measurement PCR-10 chain replay (Keylime-compatible)
//! - IOMMU / Thunderbolt / PCIe DMA attack surface validation
//! - Air-gapped operation with ML-DSA-65 signed offline bundles & hardware token presence

pub mod proximity_shield;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sppio_behavioral_ai::{
    BehavioralAssessment, KeystrokeSample, ThreatVerdict, WaylandSurfaceTelemetry,
    assess_keystroke_window, assess_overlay_telemetry,
};
use sppio_pqc::{AirGappedBundle, PqcError};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TamperTrigger {
    ChassisIntrusion,
    LidTamper,
    AttestationFailure,
    UnexpectedShutdown,
    BpfLsmViolation,
    BadUsbInjection,
    DmaUnauthorizedDevice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroizationReceipt {
    pub triggered_by: TamperTrigger,
    pub fde_key_scrubbed: bool,
    pub session_key_scrubbed: bool,
    pub pqc_secret_scrubbed: bool,
    pub lockdown_engaged: bool,
}

/// Memory-safe key vault that guarantees cryptographic zeroization on drop or tamper.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VolatileKeyVault {
    fde_master_key: [u8; 32],
    exam_session_key: [u8; 32],
    pqc_ephemeral_secret: [u8; 32],
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
            zeroized: false,
            lockdown_engaged: false,
        }
    }

    pub fn is_zeroized(&self) -> bool {
        self.zeroized
    }

    pub fn is_locked_down(&self) -> bool {
        self.lockdown_engaged
    }

    /// Loads live exam/PQC/FDE key material from a runtime directory (if present).
    pub fn load_from_runtime_dir(dir: &str) -> Self {
        let read_32 = |name: &str| -> [u8; 32] {
            let mut buf = [0u8; 32];
            if let Ok(bytes) = std::fs::read(std::path::Path::new(dir).join(name)) {
                let n = bytes.len().min(32);
                buf[..n].copy_from_slice(&bytes[..n]);
            }
            buf
        };
        Self::initialize(
            read_32("fde.key"),
            read_32("session.key"),
            read_32("pqc.key"),
        )
    }

    /// Immediately scrubs all sensitive key material in RAM and engages hardware lockdown.
    pub fn tamper_zeroize(&mut self, trigger: TamperTrigger) -> ZeroizationReceipt {
        self.fde_master_key.zeroize();
        self.exam_session_key.zeroize();
        self.pqc_ephemeral_secret.zeroize();
        self.zeroized = true;
        self.lockdown_engaged = true;

        // Unlink ephemeral runtime keys, drop kernel page cache, and suspend LUKS root if active.
        for name in ["fde.key", "session.key", "pqc.key"] {
            let p = std::path::Path::new("/run/examos/keys").join(name);
            if p.exists() {
                let _ = std::fs::write(&p, [0u8; 32]);
                let _ = std::fs::remove_file(&p);
            }
        }
        let _ = std::fs::write("/proc/sys/vm/drop_caches", "3\n");
        if std::path::Path::new("/dev/mapper/examos-root").exists() {
            let _ = std::process::Command::new("cryptsetup")
                .args(["luksSuspend", "examos-root"])
                .output();
        }
        ZeroizationReceipt {
            triggered_by: trigger,
            fde_key_scrubbed: self.fde_master_key == [0u8; 32],
            session_key_scrubbed: self.exam_session_key == [0u8; 32],
            pqc_secret_scrubbed: self.pqc_ephemeral_secret == [0u8; 32],
            lockdown_engaged: self.lockdown_engaged,
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

/// Replays Linux IMA PCR-10 extension chain and verifies every measured file against an allowlist.
pub fn verify_ima_measurements(
    ascii_log: &str,
    expected_pcr10_hex: &str,
    allowlist_sha256: &[(&str, &str)],
) -> Result<Vec<ImaMeasurementEntry>, String> {
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
            .unwrap_or(parts[3])
            .to_string();
        let file_path = parts[4].to_string();

        // Keylime / IMA allowlist check for critical paths
        if let Some((_, expected_digest)) = allowlist_sha256.iter().find(|(p, _)| *p == file_path) {
            if !file_digest_part.eq_ignore_ascii_case(expected_digest) {
                return Err(format!(
                    "IMA allowlist mismatch for {}: expected {}, got {}",
                    file_path, expected_digest, file_digest_part
                ));
            }
        }

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

    let replayed_hex = hex::encode(pcr10);
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
        let t1 = hex::encode(Sha256::digest(b"template-1"));
        let f1 = hex::encode(Sha256::digest(b"examos-kiosk-bin"));
        let line = format!("10 {t1} ima-ng sha256:{f1} /usr/local/bin/examos-kiosk\n");

        let mut pcr10 = [0u8; 32];
        let mut h = Sha256::new();
        h.update(pcr10);
        h.update(hex::decode(&t1).unwrap());
        pcr10.copy_from_slice(&h.finalize());
        let expected_pcr = hex::encode(pcr10);

        let allowlist = [("/usr/local/bin/examos-kiosk", f1.as_str())];
        let parsed = verify_ima_measurements(&line, &expected_pcr, &allowlist).expect("valid IMA");
        assert_eq!(parsed.len(), 1);

        let bad_allowlist = [("/usr/local/bin/examos-kiosk", "0000000000000000000000000000000000000000000000000000000000000000")];
        assert!(verify_ima_measurements(&line, &expected_pcr, &bad_allowlist).is_err());
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
