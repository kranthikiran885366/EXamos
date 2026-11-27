#![forbid(unsafe_code)]
use std::fs;
use std::path::Path;
use sppio_pqc::{AirGappedBundle, DsaKeypair, KemKeypair};
use sppio_securityd::{
    DmaPosture, TamperTrigger, VolatileKeyVault, enforce_dma_policy,
    verify_airgapped_update, verify_ima_measurements,
};

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
        _ => TamperTrigger::UnexpectedShutdown,
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
            let log_path = args.get(2).expect("usage: verify-ima <ascii_log_path> <expected_pcr10_hex>");
            let expected_pcr = args.get(3).expect("expected_pcr10_hex required");
            let ascii_log = fs::read_to_string(log_path).expect("failed to read IMA log");
            match verify_ima_measurements(&ascii_log, expected_pcr, &[]) {
                Ok(entries) => println!("{{\"ima_verified\":true,\"entries\":{}}}", entries.len()),
                Err(e) => {
                    eprintln!("{{\"ima_verified\":false,\"error\":\"{e}\"}}");
                    std::process::exit(1);
                }
            }
        }
        "verify-bundle" => {
            let bundle_path = args.get(2).expect("usage: verify-bundle <bundle.json> <vk_hex> [--smartcard-verified]");
            let vk_hex = args.get(3).expect("verifying key hex required");
            let smartcard_ok = args.iter().any(|a| a == "--smartcard-verified");
            let raw = fs::read_to_string(bundle_path).expect("failed to read bundle JSON");
            let bundle: AirGappedBundle = serde_json::from_str(&raw).expect("invalid bundle JSON");
            let vk_bytes = hex::decode(vk_hex).expect("invalid vk hex");
            match verify_airgapped_update(&bundle, &vk_bytes, smartcard_ok) {
                Ok(payload) => println!("{{\"bundle_verified\":true,\"bytes\":{}}}", payload.len()),
                Err(e) => {
                    eprintln!("{{\"bundle_verified\":false,\"error\":\"{e}\"}}");
                    std::process::exit(1);
                }
            }
        }
        "check-dma" => {
            let posture = read_linux_dma_posture();
            let mut vault = VolatileKeyVault::initialize([0x01; 32], [0x02; 32], [0x03; 32]);
            match enforce_dma_policy(&posture, &mut vault) {
                Ok(()) => println!("{}", serde_json::to_string(&posture).unwrap()),
                Err(receipt) => {
                    eprintln!("{}", serde_json::to_string(&receipt).unwrap());
                    std::process::exit(1);
                }
            }
        }
        "tamper-zeroize" => {
            let trigger_name = args
                .windows(2)
                .find(|w| w[0] == "--trigger")
                .map(|w| w[1].as_str())
                .unwrap_or("UnexpectedShutdown");
            let mut vault = VolatileKeyVault::initialize([0xFF; 32], [0xEE; 32], [0xDD; 32]);
            let receipt = vault.tamper_zeroize(parse_trigger(trigger_name));
            println!("{}", serde_json::to_string(&receipt).unwrap());
        }
        "--daemon" => {
            let posture = read_linux_dma_posture();
            println!(
                "{{\"daemon\":\"sppio-securityd\",\"mode\":\"daemon\",\"iommu_enabled\":{},\"iommu_strict\":{}}}",
                posture.iommu_enabled, posture.iommu_strict
            );
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        }
        _ => {
            println!("sppio-securityd v{} [--self-test | verify-ima | verify-bundle | check-dma | tamper-zeroize | --daemon]", env!("CARGO_PKG_VERSION"));
        }
    }
}
