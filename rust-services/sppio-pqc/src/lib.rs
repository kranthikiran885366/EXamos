#![forbid(unsafe_code)]
//! SPPIO Post-Quantum Cryptography Module
//!
//! Provides NIST-standardized post-quantum primitives:
//! - FIPS 203: ML-KEM-768 key encapsulation mechanism (data-in-transit & FDE key wrapping)
//! - FIPS 204: ML-DSA-65 digital signatures (OS updates, attestation, air-gapped bundles)
//! - Zeroized secret key and shared-secret handling (`zeroize::Zeroize`)

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ml_dsa::{
    B32, KeyGen as DsaKeyGen, MlDsa65,
    signature::{Signer, Verifier},
};
use ml_kem::{
    EncodedSizeUser, KemCore, MlKem768,
    kem::{Decapsulate, Encapsulate},
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

/// OS-backed CSPRNG implementing `rand_core::{RngCore, CryptoRng}`.
#[derive(Default)]
pub struct OsCsprng;

impl RngCore for OsCsprng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("OS CSPRNG failure");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("OS CSPRNG failure");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OS CSPRNG failure");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(|e| {
            let code = core::num::NonZeroU32::new(e.raw_os_error().unwrap_or(1) as u32)
                .unwrap_or(core::num::NonZeroU32::MIN);
            rand_core::Error::from(code)
        })
    }
}

impl CryptoRng for OsCsprng {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcError {
    InvalidKeyEncoding(&'static str),
    InvalidCiphertext(&'static str),
    InvalidSignature(&'static str),
    DigestMismatch,
    SignatureRejected,
}

impl core::fmt::Display for PqcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyEncoding(m) => write!(f, "invalid PQC key encoding: {m}"),
            Self::InvalidCiphertext(m) => write!(f, "invalid PQC ciphertext: {m}"),
            Self::InvalidSignature(m) => write!(f, "invalid PQC signature: {m}"),
            Self::DigestMismatch => write!(f, "bundle SHA3-256 digest mismatch"),
            Self::SignatureRejected => write!(f, "ML-DSA-65 signature verification failed"),
        }
    }
}

impl std::error::Error for PqcError {}

/// ML-KEM-768 (FIPS 203) encapsulated shared secret + keypair wrapper.
pub struct KemKeypair {
    dk_bytes: Vec<u8>,
    pub ek_bytes: Vec<u8>,
}

impl Drop for KemKeypair {
    fn drop(&mut self) {
        self.dk_bytes.zeroize();
    }
}

impl KemKeypair {
    /// Generate a fresh ML-KEM-768 keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut rng = OsCsprng;
        let (dk, ek) = MlKem768::generate(&mut rng);
        Self {
            dk_bytes: dk.as_bytes().to_vec(),
            ek_bytes: ek.as_bytes().to_vec(),
        }
    }

    /// Encapsulate a 32-byte shared secret to a recipient's ML-KEM-768 encapsulation key.
    pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), PqcError> {
        let ek_arr = ek_bytes
            .try_into()
            .map_err(|_| PqcError::InvalidKeyEncoding("ML-KEM-768 encapsulation key length"))?;
        let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(ek_arr);
        let mut rng = OsCsprng;
        let (ct, ss) = ek
            .encapsulate(&mut rng)
            .map_err(|_| PqcError::InvalidCiphertext("encapsulation failed"))?;
        let mut shared = [0u8; 32];
        shared.copy_from_slice(ss.as_slice());
        Ok((ct.as_slice().to_vec(), shared))
    }

    /// Decapsulate an ML-KEM-768 ciphertext using this keypair's decapsulation key.
    pub fn decapsulate(&self, ct_bytes: &[u8]) -> Result<[u8; 32], PqcError> {
        let dk_arr = self
            .dk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PqcError::InvalidKeyEncoding("ML-KEM-768 decapsulation key length"))?;
        let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(dk_arr);
        let ct = ct_bytes
            .try_into()
            .map_err(|_| PqcError::InvalidCiphertext("ML-KEM-768 ciphertext length"))?;
        let ss = dk
            .decapsulate(ct)
            .map_err(|_| PqcError::InvalidCiphertext("decapsulation failed"))?;
        let mut shared = [0u8; 32];
        shared.copy_from_slice(ss.as_slice());
        Ok(shared)
    }
}

/// ML-DSA-65 (FIPS 204) signing keypair.
pub struct DsaKeypair {
    seed: [u8; 32],
    pub vk_bytes: Vec<u8>,
}

impl Drop for DsaKeypair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl DsaKeypair {
    /// Generate a fresh ML-DSA-65 keypair from 32 bytes of OS CSPRNG entropy.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsCsprng.fill_bytes(&mut seed);
        let xi = B32::from(seed);
        let kp = MlDsa65::from_seed(&xi);
        let vk_bytes = kp.verifying_key().encode().as_slice().to_vec();
        Self { seed, vk_bytes }
    }

    /// Sign a message with ML-DSA-65 (FIPS 204).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let xi = B32::from(self.seed);
        let kp = MlDsa65::from_seed(&xi);
        let sig = kp.signing_key().sign(message);
        sig.encode().as_slice().to_vec()
    }

    /// Verify an ML-DSA-65 signature against a verifying key.
    pub fn verify(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<(), PqcError> {
        let vk_enc = vk_bytes
            .try_into()
            .map_err(|_| PqcError::InvalidKeyEncoding("ML-DSA-65 verifying key length"))?;
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(vk_enc);
        let sig_enc = sig_bytes
            .try_into()
            .map_err(|_| PqcError::InvalidSignature("ML-DSA-65 signature length"))?;
        let sig = ml_dsa::Signature::<MlDsa65>::decode(sig_enc)
            .ok_or(PqcError::InvalidSignature("malformed ML-DSA-65 signature"))?;
        vk.verify(message, &sig)
            .map_err(|_| PqcError::SignatureRejected)
    }
}

/// Air-gapped signed update/exam bundle (`.sppio-bundle`) verified offline with ML-DSA-65.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirGappedBundle {
    pub bundle_id: String,
    pub target_slot: String,
    pub version: String,
    pub sha3_256_digest: String,
    pub payload_base64: String,
    pub signature_algorithm: String,
    pub signature_base64: String,
}

impl AirGappedBundle {
    pub fn create_signed(
        bundle_id: &str,
        target_slot: &str,
        version: &str,
        payload: &[u8],
        signer: &DsaKeypair,
    ) -> Self {
        let digest = hex::encode(Sha3_256::digest(payload));
        let canonical = format!(
            "sppio-airgap-v1|{}|{}|{}|{}",
            bundle_id, target_slot, version, digest
        );
        let sig = signer.sign(canonical.as_bytes());
        Self {
            bundle_id: bundle_id.to_string(),
            target_slot: target_slot.to_string(),
            version: version.to_string(),
            sha3_256_digest: digest,
            payload_base64: B64.encode(payload),
            signature_algorithm: "ML-DSA-65".to_string(),
            signature_base64: B64.encode(sig),
        }
    }

    pub fn verify_offline(&self, vk_bytes: &[u8]) -> Result<Vec<u8>, PqcError> {
        if self.signature_algorithm != "ML-DSA-65" {
            return Err(PqcError::InvalidSignature("unsupported signature algorithm"));
        }
        let payload = B64
            .decode(&self.payload_base64)
            .map_err(|_| PqcError::InvalidCiphertext("invalid payload base64"))?;
        let actual_digest = hex::encode(Sha3_256::digest(&payload));
        if actual_digest != self.sha3_256_digest {
            return Err(PqcError::DigestMismatch);
        }
        let sig_bytes = B64
            .decode(&self.signature_base64)
            .map_err(|_| PqcError::InvalidSignature("invalid signature base64"))?;
        let canonical = format!(
            "sppio-airgap-v1|{}|{}|{}|{}",
            self.bundle_id, self.target_slot, self.version, self.sha3_256_digest
        );
        DsaKeypair::verify(vk_bytes, canonical.as_bytes(), &sig_bytes)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_768_round_trip_and_tamper_isolation() {
        let kp = KemKeypair::generate();
        let (mut ct, ss_sender) = KemKeypair::encapsulate(&kp.ek_bytes).expect("encapsulate");
        let ss_receiver = kp.decapsulate(&ct).expect("decapsulate");
        assert_eq!(ss_sender, ss_receiver);

        // Implicit rejection: tampering with ciphertext produces a different shared secret
        ct[0] ^= 0xFF;
        let ss_tampered = kp.decapsulate(&ct).expect("implicit rejection decaps");
        assert_ne!(ss_sender, ss_tampered);
    }

    #[test]
    fn ml_dsa_65_sign_verify_and_tamper_rejection() {
        let kp = DsaKeypair::generate();
        let msg = b"sppio-os-release-2.19.0-dm-verity-roothash";
        let sig = kp.sign(msg);
        assert!(DsaKeypair::verify(&kp.vk_bytes, msg, &sig).is_ok());

        let tampered = b"sppio-os-release-2.19.0-dm-verity-tampered";
        assert_eq!(
            DsaKeypair::verify(&kp.vk_bytes, tampered, &sig),
            Err(PqcError::SignatureRejected)
        );
    }

    #[test]
    fn airgapped_bundle_offline_verification_and_tamper_rejection() {
        let kp = DsaKeypair::generate();
        let payload = b"SQUASHFS_IMAGE_BYTES_VERIFIED";
        let mut bundle =
            AirGappedBundle::create_signed("bnd-001", "SLOT_B", "2.19.0", payload, &kp);
        let verified = bundle.verify_offline(&kp.vk_bytes).expect("valid bundle");
        assert_eq!(verified, payload);

        bundle.payload_base64 = B64.encode(b"SQUASHFS_IMAGE_BYTES_TAMPERED");
        assert_eq!(
            bundle.verify_offline(&kp.vk_bytes),
            Err(PqcError::DigestMismatch)
        );
    }
}
