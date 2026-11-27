#![forbid(unsafe_code)]
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use sppio_pqc::{AirGappedBundle, DsaKeypair, KemKeypair};
use sppio_securityd::canary_tripwire::CanaryMonitor;
use sppio_securityd::proximity_shield::{
    capture_mic_pcm, capture_webcam_luma, AcousticUltrasonicShield, AlertSeverity,
    BusDisplayGuard, ProximityReport, RfShieldMonitor, ShieldSubsystem, VisionGlareDetector,
};
use sppio_securityd::tpm_log_chain::{
    enforce_hardware_kill_switches, KillSwitchPolicy, TpmLogChain,
};
use sppio_securityd::{
    enforce_dma_policy, replay_ima_pcr10, verify_airgapped_update, verify_ima_measurements,
    DmaPosture, TamperTrigger, VolatileKeyVault, DEFAULT_KEY_DIR,
};

const BUS_BASELINE_PATH: &str = "/run/examos/bus-baseline.json";

fn read_linux_dma_posture() -> DmaPosture {
    let iommu_enabled = Path::new("/sys/class/iommu")
        .read_dir()
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let iommu_strict = cmdline.contains("iommu.strict=1") || cmdline.contains("intel_iommu=on");

    let mut tb_auth = 0u32;
    if let Ok(entries) = Path::new("/sys/bus/thunderbolt/devices").read_dir() {
        for entry in entries.flatten() {
            let auth_path = entry.path().join("authorized");
            if let Ok(val) = fs::read_to_string(auth_path) {
                if val.trim() == "1" {
                    tb_auth += 1;
                }
            }
        }
    }

    DmaPosture {
        iommu_enabled,
        iommu_strict,
        thunderbolt_authorized_count: tb_auth,
        unapproved_pcie_dma_devices: vec![],
    }
}

fn parse_trigger(s: &str) -> TamperTrigger {
    match s {
        "ChassisIntrusion" => TamperTrigger::ChassisIntrusion,
        "LidTamper" => TamperTrigger::LidTamper,
        "AttestationFailure" => TamperTrigger::AttestationFailure,
        "BpfLsmViolation" => TamperTrigger::BpfLsmViolation,
        "BadUsbInjection" => TamperTrigger::BadUsbInjection,
        "DmaUnauthorizedDevice" => TamperTrigger::DmaUnauthorizedDevice,
        "CanaryTripwire" => TamperTrigger::CanaryTripwire,
        _ => TamperTrigger::UnexpectedShutdown,
    }
}

fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].as_str())
}

fn fatal(message: &str) -> ! {
    let payload = serde_json::json!({ "error": message });
    eprintln!("{payload}");
    std::process::exit(1);
}

/// Loads a `path sha256` or `sha256 path` allowlist. Duplicate paths are
/// rejected so a later line cannot silently override an earlier digest.
fn parse_ima_allowlist(path: &str) -> Result<Vec<(String, String)>, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("cannot read IMA allowlist {path}: {error}"))?;
    let mut entries: Vec<(String, String)> = Vec::new();

    for (line_no, raw_line) in raw.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let first = parts
            .next()
            .ok_or_else(|| format!("malformed allowlist line {}", line_no + 1))?;
        let second = parts
            .next()
            .ok_or_else(|| format!("malformed allowlist line {}", line_no + 1))?;
        if parts.next().is_some() {
            return Err(format!("trailing data on allowlist line {}", line_no + 1));
        }

        let is_digest = |value: &str| {
            value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
        };
        let (measured_path, digest) = if is_digest(first) {
            (second, first)
        } else if is_digest(second) {
            (first, second)
        } else {
            return Err(format!(
                "allowlist line {} does not contain a SHA-256 digest",
                line_no + 1
            ));
        };

        let safe_path = measured_path.starts_with('/')
            || measured_path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'));
        if !safe_path || measured_path.len() > 4096 {
            return Err(format!(
                "allowlist line {} has an invalid measured path",
                line_no + 1
            ));
        }
        if entries.iter().any(|(existing, _)| existing == measured_path) {
            return Err(format!(
                "duplicate allowlist path on line {}: {measured_path}",
                line_no + 1
            ));
        }
        entries.push((measured_path.to_string(), digest.to_ascii_lowercase()));
    }

    if entries.is_empty() {
        return Err("IMA allowlist is empty; refusing to verify without trusted paths".to_string());
    }
    Ok(entries)
}

/// Verifies a detached PKCS#11 / smartcard signature over the exact bundle
/// bytes using the token's public key. This replaces the previous trusted
/// `--smartcard-verified` boolean: possession of the flag is no longer enough.
fn verify_smartcard_signature(
    bundle_path: &str,
    signature_path: &str,
    public_key_path: &str,
) -> Result<(), String> {
    if !Path::new(signature_path).is_file() {
        return Err(format!(
            "smartcard signature file is missing: {signature_path}"
        ));
    }
    if !Path::new(public_key_path).is_file() {
        return Err(format!(
            "smartcard public key file is missing: {public_key_path}"
        ));
    }
    let payload = fs::read(bundle_path)
        .map_err(|error| format!("cannot read bundle {bundle_path}: {error}"))?;

    let mut child = Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            public_key_path,
            "-signature",
            signature_path,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot execute openssl for smartcard verification: {error}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "cannot open openssl stdin".to_string())?;
    stdin
        .write_all(&payload)
        .map_err(|error| format!("cannot feed bundle to openssl: {error}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for openssl: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "smartcard signature verification failed: {}",
            detail.trim()
        ));
    }
    Ok(())
}

fn collect_proximity(
    rf: &mut RfShieldMonitor,
    vision: &mut VisionGlareDetector,
    acoustic: &AcousticUltrasonicShield,
    bus: &BusDisplayGuard,
    now_sec: u64,
    capture_media: bool,
) -> ProximityReport {
    let mut alerts = rf.scan_linux_hardware(now_sec);
    let rf_ble_tracked = rf.tracked_ble_count();
    let rf_wifi_suspicious = alerts
        .iter()
        .filter(|alert| {
            alert.subsystem == ShieldSubsystem::RfBluetoothWifi
                && alert.code != "BLE_CLOSE_PROXIMITY"
        })
        .count();

    let mut vision_glare_score = 0.0;
    let mut ultrasonic_doppler_ratio = 0.0;
    if capture_media {
        if let Some((luma, width, height)) = capture_webcam_luma() {
            let (score, vision_alerts) =
                vision.analyze_luma_frame(&luma, width, height, now_sec);
            vision_glare_score = score;
            alerts.extend(vision_alerts);
        }
        if let Some(pcm) = capture_mic_pcm() {
            let (ratio, acoustic_alerts) = acoustic.analyze_mic_pcm(&pcm, now_sec);
            ultrasonic_doppler_ratio = ratio;
            alerts.extend(acoustic_alerts);
        }
    }

    let (external_displays_connected, unauthorized_usb_devices, bus_alerts) = bus.scan(now_sec);
    alerts.extend(bus_alerts);

    ProximityReport {
        rf_ble_tracked,
        rf_wifi_suspicious,
        vision_glare_score,
        ultrasonic_doppler_ratio,
        external_displays_connected,
        unauthorized_usb_devices,
        alerts,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("--help");

    match cmd {
        "--self-test" => {
            let kem = KemKeypair::generate();
            let (ct, ss1) = KemKeypair::encapsulate(&kem.ek_bytes).expect("ML-KEM-768 encapsulate");
            let ss2 = kem.decapsulate(&ct).expect("ML-KEM-768 decapsulate");
            assert_eq!(ss1, ss2);

            let dsa = DsaKeypair::generate();
            let sig = dsa.sign(b"sppio-securityd-boot-check");
            DsaKeypair::verify(&dsa.vk_bytes, b"sppio-securityd-boot-check", &sig)
                .expect("ML-DSA-65 verify");

            let mut vault = VolatileKeyVault::initialize([0x5A; 32], ss1, [0xA5; 32]);
            let clean_dma = DmaPosture {
                iommu_enabled: true,
                iommu_strict: true,
                thunderbolt_authorized_count: 0,
                unapproved_pcie_dma_devices: vec![],
            };
            enforce_dma_policy(&clean_dma, &mut vault).expect("DMA posture clean");
            println!(
                "{{\"daemon\":\"sppio-securityd\",\"pqc\":[\"ML-KEM-768\",\"ML-DSA-65\"],\"status\":\"READY\"}}"
            );
        }
        "verify-ima" => {
            let log_path = args.get(2).unwrap_or_else(|| {
                fatal("usage: verify-ima <ascii_log_path> <expected_pcr10_hex> <allowlist_path>")
            });
            let expected_pcr = args.get(3).unwrap_or_else(|| {
                fatal("usage: verify-ima <ascii_log_path> <expected_pcr10_hex> <allowlist_path>")
            });
            let allowlist_path = args.get(4).unwrap_or_else(|| {
                fatal("usage: verify-ima <ascii_log_path> <expected_pcr10_hex> <allowlist_path>")
            });
            let ascii_log = match fs::read_to_string(log_path) {
                Ok(log) => log,
                Err(error) => fatal(&format!("failed to read IMA log: {error}")),
            };
            let allowlist = match parse_ima_allowlist(allowlist_path) {
                Ok(list) => list,
                Err(error) => fatal(&error),
            };
            let allowlist_refs: Vec<(&str, &str)> = allowlist
                .iter()
                .map(|(path, digest)| (path.as_str(), digest.as_str()))
                .collect();
            match verify_ima_measurements(&ascii_log, expected_pcr, &allowlist_refs) {
                Ok(entries) => println!("{{\"ima_verified\":true,\"entries\":{}}}", entries.len()),
                Err(e) => fatal(&e),
            }
        }
        "replay-ima" => {
            let log_path = args
                .get(2)
                .unwrap_or_else(|| fatal("usage: replay-ima <ascii_log_path>"));
            let ascii_log = match fs::read_to_string(log_path) {
                Ok(log) => log,
                Err(error) => fatal(&format!("failed to read IMA log: {error}")),
            };
            match replay_ima_pcr10(&ascii_log, None) {
                Ok((entries, replayed)) => println!(
                    "{{\"entry_count\":{},\"replayed_pcr10_hex\":\"{replayed}\"}}",
                    entries.len()
                ),
                Err(e) => fatal(&e),
            }
        }
        "verify-bundle" => {
            let bundle_path = args.get(2).unwrap_or_else(|| {
                fatal(
                    "usage: verify-bundle <bundle.json> <vk_hex> \
                     --smartcard-pubkey <public_key.pem> --smartcard-signature <signature.bin>",
                )
            });
            let vk_hex = args.get(3).unwrap_or_else(|| {
                fatal(
                    "usage: verify-bundle <bundle.json> <vk_hex> \
                     --smartcard-pubkey <public_key.pem> --smartcard-signature <signature.bin>",
                )
            });
            let smartcard_pubkey = flag_value(&args, "--smartcard-pubkey").unwrap_or_else(|| {
                fatal("verify-bundle requires --smartcard-pubkey <public_key.pem>")
            });
            let smartcard_signature =
                flag_value(&args, "--smartcard-signature").unwrap_or_else(|| {
                    fatal("verify-bundle requires --smartcard-signature <signature.bin>")
                });

            if let Err(error) =
                verify_smartcard_signature(bundle_path, smartcard_signature, smartcard_pubkey)
            {
                fatal(&error);
            }

            let raw = match fs::read_to_string(bundle_path) {
                Ok(raw) => raw,
                Err(error) => fatal(&format!("failed to read bundle JSON: {error}")),
            };
            let bundle: AirGappedBundle = match serde_json::from_str(&raw) {
                Ok(bundle) => bundle,
                Err(error) => fatal(&format!("invalid bundle JSON: {error}")),
            };
            let vk_bytes = match hex::decode(vk_hex) {
                Ok(bytes) => bytes,
                Err(error) => fatal(&format!("invalid verifying key hex: {error}")),
            };
            match verify_airgapped_update(&bundle, &vk_bytes, true) {
                Ok(payload) => println!("{{\"bundle_verified\":true,\"bytes\":{}}}", payload.len()),
                Err(e) => fatal(&e),
            }
        }
        "check-dma" => {
            let posture = read_linux_dma_posture();
            let mut vault = if let Some(dir) = flag_value(&args, "--key-dir") {
                VolatileKeyVault::try_load_from_runtime_dir(dir)
            } else {
                VolatileKeyVault::from_os_random()
            }
            .unwrap_or_else(|error| fatal(&format!("cannot initialise key vault: {error}")));

            match enforce_dma_policy(&posture, &mut vault) {
                Ok(()) => println!("{}", serde_json::to_string(&posture).unwrap()),
                Err(receipt) => {
                    eprintln!("{}", serde_json::to_string(&receipt).unwrap());
                    std::process::exit(1);
                }
            }
        }
        "tamper-zeroize" => {
            let trigger_name = flag_value(&args, "--trigger").unwrap_or("UnexpectedShutdown");
            let key_dir = flag_value(&args, "--key-dir").unwrap_or(DEFAULT_KEY_DIR);
            let trigger = parse_trigger(trigger_name);

            let load_error = match VolatileKeyVault::try_load_from_runtime_dir(key_dir) {
                Ok(mut vault) => {
                    let receipt = vault.tamper_zeroize(trigger);
                    println!("{}", serde_json::to_string(&receipt).unwrap());
                    if receipt.wipe_errors.is_empty() {
                        return;
                    }
                    receipt.wipe_errors.join("; ")
                }
                Err(error) => {
                    // Still attempt to scrub whatever key files are present.
                    let mut vault = VolatileKeyVault::initialize([0; 32], [0; 32], [0; 32])
                        .with_key_dir(key_dir);
                    let mut receipt = vault.tamper_zeroize(trigger);
                    receipt.wipe_errors.insert(
                        0,
                        format!("runtime key material unavailable: {error}"),
                    );
                    println!("{}", serde_json::to_string(&receipt).unwrap());
                    receipt.wipe_errors.join("; ")
                }
            };
            fatal(&format!("zeroization incomplete: {load_error}"));
        }
        "proximity-scan" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let telemetry_path = "/run/examos/proximity-telemetry.json";
            if let Ok(raw) = fs::read_to_string(telemetry_path) {
                if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let ts = val.get("timestamp_sec").and_then(|v| v.as_u64()).unwrap_or(0);
                    let degraded = now.saturating_sub(ts) > 10;
                    if let Some(obj) = val.as_object_mut() {
                        obj.insert(
                            "status".to_string(),
                            serde_json::Value::String(if degraded { "DEGRADED" } else { "OK" }.to_string()),
                        );
                    }
                    println!("{}", serde_json::to_string(&val).unwrap());
                    return;
                }
            }
            let mut rf = RfShieldMonitor::new(vec![]);
            let mut vision = VisionGlareDetector::new();
            let acoustic = AcousticUltrasonicShield::new();
            let bus = BusDisplayGuard::load_or_capture_baseline(BUS_BASELINE_PATH);
            let report = collect_proximity(&mut rf, &mut vision, &acoustic, &bus, now, true);
            let mut val = serde_json::to_value(&report).unwrap();
            if let Some(obj) = val.as_object_mut() {
                obj.insert("timestamp_sec".to_string(), serde_json::json!(now));
                obj.insert("status".to_string(), serde_json::json!("DEGRADED"));
            }
            println!("{}", serde_json::to_string(&val).unwrap());
        }
        "verify-log-chain" => {
            let log_path = args
                .get(2)
                .unwrap_or_else(|| fatal("usage: verify-log-chain <chain.jsonl> <vk_hex>"));
            let vk_hex = args
                .get(3)
                .unwrap_or_else(|| fatal("usage: verify-log-chain <chain.jsonl> <vk_hex>"));
            let vk_bytes = match hex::decode(vk_hex) {
                Ok(bytes) => bytes,
                Err(error) => fatal(&format!("invalid verifying key hex: {error}")),
            };
            match TpmLogChain::verify_file(log_path, &vk_bytes) {
                Ok(count) => println!("{{\"log_chain_verified\":true,\"entries\":{count}}}"),
                Err(e) => fatal(&e),
            }
        }
        "--daemon" => {
            let key_dir =
                std::env::var("EXAMOS_KEY_DIR").unwrap_or_else(|_| DEFAULT_KEY_DIR.to_string());
            let mut vault = match VolatileKeyVault::try_load_from_runtime_dir(&key_dir) {
                Ok(vault) => vault,
                Err(error) => {
                    if std::env::var("EXAMOS_ALLOW_EPHEMERAL_KEYS").as_deref() == Ok("1") {
                        eprintln!(
                            "[sppio-securityd] key material unavailable ({error}); \
                             EXAMOS_ALLOW_EPHEMERAL_KEYS=1, using ephemeral keys"
                        );
                        VolatileKeyVault::from_os_random()
                            .unwrap_or_else(|error| fatal(&error))
                    } else {
                        fatal(&format!(
                            "refusing to start without key material in {key_dir}: {error}"
                        ));
                    }
                }
            };
            let mut rf = RfShieldMonitor::new(vec![]);
            let mut vision = VisionGlareDetector::new();
            let acoustic = AcousticUltrasonicShield::new();
            let bus = BusDisplayGuard::load_or_capture_baseline(BUS_BASELINE_PATH);
            let mut canary = CanaryMonitor::deploy(
                &[
                    "/var/lib/examos/.canary_exam_keys.json",
                    "/etc/examos/.canary_admin_token",
                    "/tmp/.examos_db_dump.sql",
                ],
                Some(64443),
            );
            let dsa_kp = DsaKeypair::generate();
            let mut log_chain = TpmLogChain::open_or_init("/var/log/examos/tpm-chained.jsonl", dsa_kp);

            let _ = enforce_hardware_kill_switches(&KillSwitchPolicy {
                allow_mic: std::env::var("EXAMOS_ALLOW_MIC").as_deref() == Ok("1"),
                allow_camera: std::env::var("EXAMOS_ALLOW_CAMERA").as_deref() == Ok("1"),
                allow_wifi: std::env::var("EXAMOS_ALLOW_WIFI").as_deref() == Ok("1"),
                allow_bluetooth: std::env::var("EXAMOS_ALLOW_BT").as_deref() == Ok("1"),
            });

            println!(
                "{{\"daemon\":\"sppio-securityd\",\"mode\":\"daemon\",\"proximity_shield\":\"ACTIVE\",\"canary\":\"ACTIVE\"}}"
            );
            let mut tick: u64 = 0;
            loop {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let posture = read_linux_dma_posture();
                if let Err(receipt) = enforce_dma_policy(&posture, &mut vault) {
                    let _ = log_chain.append("DMA_TAMPER_ZEROIZE", "unauthorized_dma", now);
                    eprintln!("{}", serde_json::to_string(&receipt).unwrap());
                    break;
                }

                let canary_hits = canary.check();
                if !canary_hits.is_empty() {
                    let detail = serde_json::to_string(&canary_hits).unwrap_or_default();
                    let _ = log_chain.append("CANARY_TRIPWIRE_TRIGGERED", &detail, now);
                    let receipt = vault.tamper_zeroize(TamperTrigger::CanaryTripwire);
                    eprintln!("{}", serde_json::to_string(&receipt).unwrap());
                    break;
                }

                // RF and bus checks run every cycle; camera and microphone
                // capture is expensive, so it runs at start-up and every 30s.
                let report = collect_proximity(
                    &mut rf,
                    &mut vision,
                    &acoustic,
                    &bus,
                    now,
                    tick % 30 == 0,
                );
                if let Ok(mut val) = serde_json::to_value(&report) {
                    if let Some(obj) = val.as_object_mut() {
                        obj.insert("timestamp_sec".to_string(), serde_json::json!(now));
                    }
                    if let Ok(json) = serde_json::to_string(&val) {
                        let tmp = "/run/examos/proximity-telemetry.json.tmp";
                        if fs::write(tmp, &json).is_ok() {
                            let _ = fs::rename(tmp, "/run/examos/proximity-telemetry.json");
                        }
                    }
                }
                let alerts = report.alerts;

                if alerts
                    .iter()
                    .any(|a| a.severity == AlertSeverity::CriticalTamper)
                {
                    let detail = serde_json::to_string(&alerts).unwrap_or_default();
                    let _ = log_chain.append("CRITICAL_PROXIMITY_TAMPER", &detail, now);
                    let receipt = vault.tamper_zeroize(TamperTrigger::BadUsbInjection);
                    eprintln!("{}", serde_json::to_string(&receipt).unwrap());
                    break;
                }
                if !alerts.is_empty() {
                    let detail = serde_json::to_string(&alerts).unwrap_or_default();
                    let _ = log_chain.append("PROXIMITY_ALERT", &detail, now);
                    println!("{detail}");
                }
                tick = tick.wrapping_add(1);
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
        _ => {
            println!(
                "sppio-securityd v{} [--self-test | verify-ima | replay-ima | verify-bundle | \
                 check-dma | tamper-zeroize | proximity-scan | verify-log-chain | --daemon]",
                env!("CARGO_PKG_VERSION")
            );
        }
    }
}
