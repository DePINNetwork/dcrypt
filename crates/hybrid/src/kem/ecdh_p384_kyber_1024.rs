// File: crates/hybrid/src/kem/ecdh_p384_kyber_1024.rs

//! Hybrid KEM combining ECDH on P-384 and Kyber-1024.

use super::engine::{HybridCiphertext, HybridKemEngine, HybridPublicKey, HybridSecretKey};
use dcrypt_api::{error::Result as ApiResult, Kem};
use dcrypt_kem::{ecdh::EcdhP384, kyber::{Kyber1024, KyberSharedSecret}};
use rand::{CryptoRng, RngCore};

/// A concrete hybrid KEM struct for EcdhP384 + Kyber1024.
pub struct EcdhP384Kyber1024;

impl Kem for EcdhP384Kyber1024 {
    // Define associated types using the generic building blocks
    type PublicKey = HybridPublicKey<EcdhP384, Kyber1024>;
    type SecretKey = HybridSecretKey<EcdhP384, Kyber1024>;
    type SharedSecret = KyberSharedSecret;
    type Ciphertext = HybridCiphertext<EcdhP384, Kyber1024>;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "EcdhP384-Kyber1024"
    }

    // Delegate all logic to the generic engine
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        HybridKemEngine::<EcdhP384, Kyber1024>::keypair(rng)
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
        HybridKemEngine::<EcdhP384, Kyber1024>::encapsulate(rng, public_key)
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        HybridKemEngine::<EcdhP384, Kyber1024>::decapsulate(secret_key, ciphertext)
    }
}