//! Hybrid KEM combining ECDH on P-256 and Kyber-768.
//!
//! This KEM provides "Layer 1: Transport Security" as defined in the DePIN SDK
//! architecture. It combines a classical KEM (ECDH P-256) with a post-quantum
//! KEM (Kyber-768). The final shared secret is secure as long as at least one
//! of the underlying primitives remains unbroken.

use dcrypt_algorithms::hash::sha2::Sha256;
use dcrypt_algorithms::kdf::hkdf::Hkdf;
use dcrypt_api::{error::Error as ApiError, error::Result as ApiResult, Kem, Key as ApiKey};
use dcrypt_kem::{
    ecdh::p256::{EcdhP256, EcdhP256Ciphertext, EcdhP256PublicKey, EcdhP256SecretKey},
    kyber::{Kyber768, KyberCiphertext, KyberPublicKey, KyberSecretKey, KyberSharedSecret},
};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

// --- Define the new Hybrid Data Structures ---

/// A hybrid public key containing both an ECDH and a Kyber public key.
/// The byte representation is a simple concatenation of the two component keys.
#[derive(Clone, Zeroize)]
pub struct HybridPublicKey {
    pub ecdh_pk: EcdhP256PublicKey,
    pub kyber_pk: KyberPublicKey,
}

/// A hybrid secret key containing both an ECDH and a Kyber secret key.
/// Securely zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pub ecdh_sk: EcdhP256SecretKey,
    pub kyber_sk: KyberSecretKey,
}

/// A hybrid ciphertext containing both an ECDH and a Kyber ciphertext.
/// The byte representation is a concatenation of the two component ciphertexts.
#[derive(Clone)]
pub struct HybridCiphertext {
    pub ecdh_ct: EcdhP256Ciphertext,
    pub kyber_ct: KyberCiphertext,
}

// --- Implement Serialization for Hybrid Types ---

impl HybridPublicKey {
    /// Deserializes a hybrid public key from a byte slice.
    /// Expects `ECDH_PK_LEN` bytes followed by `KYBER_PK_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        const ECDH_PK_LEN: usize = 33;
        const KYBER_PK_LEN: usize = 1184;
        const TOTAL_LEN: usize = ECDH_PK_LEN + KYBER_PK_LEN;

        if bytes.len() != TOTAL_LEN {
            return Err(ApiError::InvalidLength {
                context: "HybridPublicKey::from_bytes",
                expected: TOTAL_LEN,
                actual: bytes.len(),
            });
        }
        let (ecdh_bytes, kyber_bytes) = bytes.split_at(ECDH_PK_LEN);

        Ok(Self {
            ecdh_pk: EcdhP256PublicKey::from_bytes(ecdh_bytes)?,
            kyber_pk: KyberPublicKey::from_bytes(kyber_bytes)?,
        })
    }

    /// Serializes the hybrid public key into a single byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.ecdh_pk.to_bytes(), self.kyber_pk.to_bytes()].concat()
    }
}

impl HybridCiphertext {
    /// Deserializes a hybrid ciphertext from a byte slice.
    /// Expects `ECDH_CT_LEN` bytes followed by `KYBER_CT_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        const ECDH_CT_LEN: usize = 33;
        const KYBER_CT_LEN: usize = 1088;
        const TOTAL_LEN: usize = ECDH_CT_LEN + KYBER_CT_LEN;

        if bytes.len() != TOTAL_LEN {
            return Err(ApiError::InvalidLength {
                context: "HybridCiphertext::from_bytes",
                expected: TOTAL_LEN,
                actual: bytes.len(),
            });
        }
        let (ecdh_bytes, kyber_bytes) = bytes.split_at(ECDH_CT_LEN);

        Ok(Self {
            ecdh_ct: EcdhP256Ciphertext::from_bytes(ecdh_bytes)?,
            kyber_ct: KyberCiphertext::from_bytes(kyber_bytes)?,
        })
    }

    /// Serializes the hybrid ciphertext into a single byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.ecdh_ct.to_bytes(), self.kyber_ct.to_bytes()].concat()
    }
}

// --- The Hybrid KEM struct ---

/// A hybrid Key Encapsulation Mechanism combining ECDH P-256 and Kyber-768.
pub struct EcdhKyber768;

impl Kem for EcdhKyber768 {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SharedSecret = KyberSharedSecret; // Reuse Kyber's SS type (32 bytes)
    type Ciphertext = HybridCiphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P256-Kyber768"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (ecdh_pk, ecdh_sk) = EcdhP256::keypair(rng)?;
        let (kyber_pk, kyber_sk) = Kyber768::keypair(rng)?;

        Ok((
            HybridPublicKey { ecdh_pk, kyber_pk },
            HybridSecretKey { ecdh_sk, kyber_sk },
        ))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> ApiResult<(Self::Ciphertext, Self::SharedSecret)> {
        // 1. Encapsulate for each underlying scheme
        let (ecdh_ct, ecdh_ss) = EcdhP256::encapsulate(rng, &public_key.ecdh_pk)?;
        let (kyber_ct, kyber_ss) = Kyber768::encapsulate(rng, &public_key.kyber_pk)?;

        // 2. Combine the two ciphertexts by concatenation
        let hybrid_ct = HybridCiphertext { ecdh_ct, kyber_ct };

        // 3. Combine the two shared secrets using HKDF-SHA256 for the final key
        let ikm = [
            ecdh_ss.to_bytes(), 
            kyber_ss.to_bytes_zeroizing().to_vec()  // Convert Zeroizing<Vec<u8>> to Vec<u8>
        ].concat();
        
        // Use the existing HKDF implementation
        let okm = Hkdf::<Sha256>::derive(
            None,  // No salt
            &ikm,
            Some(b"depin-hybrid-kem-shared-secret"),
            32
        ).map_err(|_| ApiError::Other {
            context: "HKDF",
            #[cfg(feature = "std")]
            message: "HKDF derivation failed".to_string(),
        })?;

        Ok((hybrid_ct, KyberSharedSecret::new(ApiKey::new(&okm))))
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        // 1. Decapsulate for each underlying scheme
        let ecdh_ss = EcdhP256::decapsulate(&secret_key.ecdh_sk, &ciphertext.ecdh_ct)?;
        let kyber_ss = Kyber768::decapsulate(&secret_key.kyber_sk, &ciphertext.kyber_ct)?;

        // 2. Combine the two shared secrets using the exact same HKDF-SHA256 construction
        let ikm = [
            ecdh_ss.to_bytes(), 
            kyber_ss.to_bytes_zeroizing().to_vec()  // Convert Zeroizing<Vec<u8>> to Vec<u8>
        ].concat();
        
        // Use the existing HKDF implementation
        let okm = Hkdf::<Sha256>::derive(
            None,  // No salt
            &ikm,
            Some(b"depin-hybrid-kem-shared-secret"),
            32
        ).map_err(|_| ApiError::Other {
            context: "HKDF",
            #[cfg(feature = "std")]
            message: "HKDF derivation failed".to_string(),
        })?;

        Ok(KyberSharedSecret::new(ApiKey::new(&okm)))
    }
}