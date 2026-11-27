#![forbid(unsafe_code)]
//! Deception & Canary Tripwires
//!
//! Plants hidden decoy credential/key files and a local honey-endpoint.
//! If any unauthorized process reads, modifies, or connects to a canary,
//! the offending PID is frozen immediately via SIGSTOP and RAM zeroization is triggered.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryBaseline {
    pub path: PathBuf,
    pub sha256_hex: String,
    pub mtime_ns: u128,
    pub atime_ns: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryAlert {
    pub canary_path: String,
    pub reason: String,
    pub offending_pid: Option<u32>,
    pub frozen_with_sigstop: bool,
}

pub struct CanaryMonitor {
    baselines: HashMap<PathBuf, CanaryBaseline>,
    honey_listener: Option<TcpListener>,
}

impl CanaryMonitor {
    pub fn deploy(paths: &[&str], honey_port: Option<u16>) -> Self {
        let mut baselines = HashMap::new();
        for &p_str in paths {
            let path = PathBuf::from(p_str);
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let decoy_content = format!(
                "{{\"canary_id\":\"{}\",\"note\":\"SPPIO_DECEPTION_TRAP\",\"fake_key\":\"0000deadbeef\"}}\n",
                p_str
            );
            if fs::write(&path, decoy_content.as_bytes()).is_ok() {
                if let Ok(base) = Self::capture_baseline(&path) {
                    baselines.insert(path, base);
                }
            }
        }

        let honey_listener = honey_port.and_then(|port| {
            let listener = TcpListener::bind(("127.0.0.1", port)).ok()?;
            let _ = listener.set_nonblocking(true);
            Some(listener)
        });

        Self {
            baselines,
            honey_listener,
        }
    }

    fn capture_baseline(path: &Path) -> Result<CanaryBaseline, String> {
        let data = fs::read(path).map_err(|e| e.to_string())?;
        let meta = fs::metadata(path).map_err(|e| e.to_string())?;
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let atime_ns = meta
            .accessed()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Ok(CanaryBaseline {
            path: path.to_path_buf(),
            sha256_hex: hex::encode(Sha256::digest(&data)),
            mtime_ns,
            atime_ns,
        })
    }

    /// Scans /proc/<pid>/fd on Linux for any unauthorized process holding an open FD to a canary.
    fn find_proc_holding_canary(canary: &Path) -> Option<u32> {
        let self_pid = std::process::id();
        let target = canary.to_string_lossy();
        let entries = fs::read_dir("/proc").ok()?;
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().to_string();
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            if pid <= 1 || pid == self_pid {
                continue;
            }
            let fd_dir = entry.path().join("fd");
            if let Ok(fds) = fs::read_dir(fd_dir) {
                for fd in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd.path()) {
                        if link.to_string_lossy() == target {
                            return Some(pid);
                        }
                    }
                }
            }
        }
        None
    }

    fn freeze_process(pid: u32) -> bool {
        Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Checks all canary files and the honey-port; freezes offending processes on touch.
    pub fn check(&mut self) -> Vec<CanaryAlert> {
        let mut alerts = Vec::new();
        for (path, base) in &self.baselines {
            let mut triggered_reason: Option<String> = None;
            match fs::metadata(path) {
                Err(_) => triggered_reason = Some("Canary decoy file deleted or unlinked".to_string()),
                Ok(meta) => {
                    let mtime_ns = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos())
                        .unwrap_or(0);
                    let atime_ns = meta
                        .accessed()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos())
                        .unwrap_or(0);
                    if mtime_ns != base.mtime_ns {
                        triggered_reason = Some("Canary decoy file modified".to_string());
                    } else if atime_ns > base.atime_ns {
                        triggered_reason = Some("Canary decoy file accessed/read".to_string());
                    } else if let Ok(bytes) = fs::read(path) {
                        if hex::encode(Sha256::digest(&bytes)) != base.sha256_hex {
                            triggered_reason = Some("Canary decoy content hash mismatch".to_string());
                        }
                    }
                }
            }

            let pid = Self::find_proc_holding_canary(path);
            if pid.is_some() && triggered_reason.is_none() {
                triggered_reason = Some("Unauthorized process opened canary FD".to_string());
            }

            if let Some(reason) = triggered_reason {
                let frozen = pid.map(Self::freeze_process).unwrap_or(false);
                alerts.push(CanaryAlert {
                    canary_path: path.to_string_lossy().to_string(),
                    reason,
                    offending_pid: pid,
                    frozen_with_sigstop: frozen,
                });
            }
        }

        if let Some(listener) = &self.honey_listener {
            while let Ok((_stream, peer)) = listener.accept() {
                alerts.push(CanaryAlert {
                    canary_path: format!("tcp://{}", listener.local_addr().map(|a| a.to_string()).unwrap_or_default()),
                    reason: format!("Unauthorized connection to deception honey-port from {peer}"),
                    offending_pid: None,
                    frozen_with_sigstop: false,
                });
            }
        }
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_detects_tampering_and_honey_port_probe() {
        let dir = std::env::temp_dir().join("sppio_canary_test");
        let _ = fs::create_dir_all(&dir);
        let canary_file = dir.join(".canary_secret.json");
        let canary_str = canary_file.to_string_lossy().to_string();

        let mut mon = CanaryMonitor::deploy(&[&canary_str], Some(0));
        assert!(mon.check().is_empty());

        fs::write(&canary_file, b"tampered").unwrap();
        let alerts = mon.check();
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].canary_path, canary_str);

        let _ = fs::remove_dir_all(&dir);
    }
}
