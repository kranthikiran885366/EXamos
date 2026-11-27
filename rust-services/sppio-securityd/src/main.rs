#![forbid(unsafe_code)]
use sppio_pqc::{DsaKeypair, KemKeypair};
use sppio_securityd::{DmaPosture, VolatileKeyVault, enforce_dma_policy};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--self-test") {
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
        return;
    }

    println!("sppio-securityd v{} ready (use --self-test for PQC & DMA posture check)", env!("CARGO_PKG_VERSION"));
}
