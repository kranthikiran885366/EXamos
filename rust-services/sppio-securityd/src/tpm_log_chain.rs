#![forbid(unsafe_code)]
//! TPM-Signed Tamper-Evident Log Chain & Hardware Kill-Switch Enforcement
//!
//! - Appends security/session events to a SHA-256 hash-chained JSONL log.
//! - Signs each entry's chain digest with ML-DSA-65 and extends TPM 2.0 PCR 15
//!   (`tpm2_pcrextend`) when `/dev/tpmrm0` is available.
//! - Enforces strict ACPI/driver kill states for microphone, camera, and Wi-Fi/BT
//!   whenever they are not authorized by the active exam policy.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sppio_pqc::DsaKeypair;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedLogEntry {
    pub seq: u64,
    pub timestamp_sec: u64,
    pub event_type: String,
    pub payload: String,
    pub prev_hash_hex: String,
    pub entry_hash_hex: String,
    pub mldsa65_sig_hex: String,
    pub tpm_pcr15_extended: bool,
}

pub struct TpmLogChain {
    log_path: PathBuf,
    seq: u64,
    head_hash_hex: String,
    signer: DsaKeypair,
}

impl TpmLogChain {
    pub fn open_or_init(log_path: &str, signer: DsaKeypair) -> Self {
        let path = PathBuf::from(log_path);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut seq = 0u64;
        let mut head_hash_hex = "0".repeat(64);
        if let Ok(raw) = fs::read_to_string(&path) {
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(entry) = serde_json::from_str::<ChainedLogEntry>(line) {
                    seq = entry.seq + 1;
                    head_hash_hex = entry.entry_hash_hex;
                }
            }
        }
        Self {
            log_path: path,
            seq,
            head_hash_hex,
            signer,
        }
    }

    pub fn verifying_key_bytes(&self) -> &[u8] {
        &self.signer.vk_bytes
    }

    fn compute_entry_hash(
        seq: u64,
        timestamp_sec: u64,
        event_type: &str,
        payload: &str,
        prev_hash_hex: &str,
    ) -> String {
        let mut h = Sha256::new();
        h.update(seq.to_be_bytes());
        h.update(timestamp_sec.to_be_bytes());
        h.update(prev_hash_hex.as_bytes());
        h.update(b"|");
        h.update(event_type.as_bytes());
        h.update(b"|");
        h.update(payload.as_bytes());
        hex::encode(h.finalize())
    }

    fn extend_tpm_pcr15(digest_hex: &str) -> bool {
        if !Path::new("/dev/tpmrm0").exists() {
            return false;
        }
        Command::new("tpm2_pcrextend")
            .args([&format!("15:sha256={digest_hex}")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn append(&mut self, event_type: &str, payload: &str, timestamp_sec: u64) -> Result<ChainedLogEntry, String> {
        let entry_hash_hex = Self::compute_entry_hash(
            self.seq,
            timestamp_sec,
            event_type,
            payload,
            &self.head_hash_hex,
        );
        let sig = self.signer.sign(entry_hash_hex.as_bytes());
        let tpm_extended = Self::extend_tpm_pcr15(&entry_hash_hex);

        let entry = ChainedLogEntry {
            seq: self.seq,
            timestamp_sec,
            event_type: event_type.to_string(),
            payload: payload.to_string(),
            prev_hash_hex: self.head_hash_hex.clone(),
            entry_hash_hex: entry_hash_hex.clone(),
            mldsa65_sig_hex: hex::encode(sig),
            tpm_pcr15_extended: tpm_extended,
        };

        let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| e.to_string())?;
        writeln!(file, "{line}").map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;

        self.seq += 1;
        self.head_hash_hex = entry_hash_hex;
        Ok(entry)
    }

    /// Verifies the entire hash chain and ML-DSA-65 signatures from genesis.
    pub fn verify_file(log_path: &str, vk_bytes: &[u8]) -> Result<usize, String> {
        let raw = fs::read_to_string(log_path).map_err(|e| e.to_string())?;
        let mut expected_prev = "0".repeat(64);
        let mut count = 0usize;

        for (idx, line) in raw.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let entry: ChainedLogEntry =
                serde_json::from_str(line).map_err(|e| format!("line {}: {e}", idx + 1))?;
            if entry.seq != idx as u64 {
                return Err(format!("sequence gap at line {}", idx + 1));
            }
            if entry.prev_hash_hex != expected_prev {
                return Err(format!("broken prev_hash at seq {}", entry.seq));
            }
            let recomputed = Self::compute_entry_hash(
                entry.seq,
                entry.timestamp_sec,
                &entry.event_type,
                &entry.payload,
                &entry.prev_hash_hex,
            );
            if recomputed != entry.entry_hash_hex {
                return Err(format!("hash tamper detected at seq {}", entry.seq));
            }
            let sig = hex::decode(&entry.mldsa65_sig_hex)
                .map_err(|_| format!("invalid sig hex at seq {}", entry.seq))?;
            DsaKeypair::verify(vk_bytes, entry.entry_hash_hex.as_bytes(), &sig)
                .map_err(|e| format!("ML-DSA-65 signature invalid at seq {}: {e}", entry.seq))?;
            expected_prev = entry.entry_hash_hex;
            count += 1;
        }
        Ok(count)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchPolicy {
    pub allow_mic: bool,
    pub allow_camera: bool,
    pub allow_wifi: bool,
    pub allow_bluetooth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchState {
    pub wifi_blocked: bool,
    pub bluetooth_blocked: bool,
    pub mic_muted: bool,
    pub camera_unbound: bool,
}

/// Enforces strict ACPI/rfkill/driver kill states whenever mic, camera, or RF are unauthorized.
pub fn enforce_hardware_kill_switches(policy: &KillSwitchPolicy) -> KillSwitchState {
    let mut state = KillSwitchState {
        wifi_blocked: false,
        bluetooth_blocked: false,
        mic_muted: false,
        camera_unbound: false,
    };

    if !policy.allow_wifi {
        state.wifi_blocked = Command::new("rfkill")
            .args(["block", "wifi"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    if !policy.allow_bluetooth {
        state.bluetooth_blocked = Command::new("rfkill")
            .args(["block", "bluetooth"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    if !policy.allow_mic {
        state.mic_muted = Command::new("amixer")
            .args(["-q", "set", "Capture", "nocap"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    if !policy.allow_camera {
        let uvc_unbind = Path::new("/sys/bus/usb/drivers/uvcvideo/unbind");
        if uvc_unbind.exists() {
            if let Ok(entries) = Path::new("/sys/bus/usb/drivers/uvcvideo").read_dir() {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.contains(':') && fs::write(uvc_unbind, name.as_bytes()).is_ok() {
                        state.camera_unbound = true;
                    }
                }
            }
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_log_chain_verifies_and_detects_tampering() {
        let dir = std::env::temp_dir().join("sppio_log_chain_test");
        let _ = fs::create_dir_all(&dir);
        let log_file = dir.join("chain.jsonl");
        let log_str = log_file.to_string_lossy().to_string();

        let kp = DsaKeypair::generate();
        let vk = kp.vk_bytes.clone();
        let mut chain = TpmLogChain::open_or_init(&log_str, kp);
        chain.append("BOOT_VERIFIED", "slot=A", 1000).unwrap();
        chain.append("PROXIMITY_OK", "alerts=0", 1005).unwrap();

        assert_eq!(TpmLogChain::verify_file(&log_str, &vk).unwrap(), 2);

        // Tamper with log file
        let tampered = fs::read_to_string(&log_file)
            .unwrap()
            .replace("alerts=0", "alerts=99");
        fs::write(&log_file, tampered).unwrap();
        assert!(TpmLogChain::verify_file(&log_str, &vk).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
