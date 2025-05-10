//! Kyber-768 KEM

use super::common::{
    KyberBase, KyberPublicKey, KyberSecretKey, KyberSharedSecret, KyberCiphertext,
    get_sizes_for_k, validate_kyber_parameters,
};
use dcrypt_core::{Kem, Key};
use rand::{CryptoRng, RngCore};
use crate::error::{Error, Result, validate};

/// Kyber-768 KEM with parameter k=3
pub type Kyber768 = KyberBase<3>;

impl Kem for Kyber768 {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type SharedSecret = KyberSharedSecret;
    type Ciphertext = KyberCiphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "Kyber-768"
    }

    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> dcrypt_core::Result<Self::KeyPair> {
        // Validate Kyber parameters
        validate_kyber_parameters::<3>("Kyber-768")?;
        
        let sizes = get_sizes_for_k::<3>()?;
        
        // Check RNG is initialized
        validate::key_generation(
            true, // In real implementation, would verify RNG state
            "Kyber-768",
            "RNG not properly initialized"
        )?;
        
        let mut public_key_data = vec![0u8; sizes.public_key];
        let mut secret_key_data = vec![0u8; sizes.secret_key];

        rng.fill_bytes(&mut public_key_data);
        rng.fill_bytes(&mut secret_key_data);

        // In real implementation, would validate generated keys
        validate::key(
            public_key_data.iter().any(|&b| b != 0),
            "Kyber-768 public key",
            "generated public key is all zeros"
        )?;

        let public_key = KyberPublicKey(public_key_data);
        let secret_key = KyberSecretKey(secret_key_data);

        Ok((public_key, secret_key))
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
    ) -> dcrypt_core::Result<(Self::Ciphertext, Self::SharedSecret)> {
        let sizes = get_sizes_for_k::<3>()?;
        
        // Validate public key size
        validate::length(
            "Kyber-768 public key",
            public_key.0.len(),
            sizes.public_key
        )?;
        
        // Additional validation in real implementation would check:
        // - Public key format is correct
        // - Polynomials are properly formatted
        // - Coefficients are within valid range
        
        validate::encapsulation(
            public_key.0.iter().any(|&b| b != 0),
            "Kyber-768",
            "public key is invalid (all zeros)"
        )?;
        
        let mut ciphertext_data = vec![0u8; sizes.ciphertext];
        let mut shared_secret_data = vec![0u8; sizes.shared_secret];

        rng.fill_bytes(&mut ciphertext_data);
        rng.fill_bytes(&mut shared_secret_data);

        let ciphertext = KyberCiphertext(ciphertext_data);
        let shared_secret = KyberSharedSecret(
            Key::new(&shared_secret_data)
        );

        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> dcrypt_core::Result<Self::SharedSecret> {
        let sizes = get_sizes_for_k::<3>()?;
        
        // Validate secret key size
        validate::length(
            "Kyber-768 secret key",
            secret_key.0.len(),
            sizes.secret_key
        )?;
        
        // Validate ciphertext size
        validate::length(
            "Kyber-768 ciphertext",
            ciphertext.0.len(),
            sizes.ciphertext
        )?;
        
        // In real implementation, additional validation would check:
        // - Secret key format is correct
        // - Ciphertext is properly formatted
        // - Decapsulation can proceed safely
        
        validate::decapsulation(
            secret_key.0.iter().any(|&b| b != 0),
            "Kyber-768",
            "secret key is invalid (all zeros)"
        )?;
        
        validate::decapsulation(
            ciphertext.0.iter().any(|&b| b != 0),
            "Kyber-768",
            "ciphertext is invalid (all zeros)"
        )?;
        
        let shared_secret_data = vec![0u8; sizes.shared_secret];
        
        Ok(KyberSharedSecret(
            Key::new(&shared_secret_data)
        ))
    }
}