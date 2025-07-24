// File: crates/kem/src/ecdh/k256.rs
//! ECDH-KEM with secp256k1 (K-256)
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the secp256k1 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.

use dcrypt_api::{Kem, Result as ApiResult, Key as ApiKey, error::Error as ApiError};
use dcrypt_common::security::SecretBuffer;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{CryptoRng, RngCore};
use crate::error::Error as KemError;
use dcrypt_algorithms::ec::k256 as ec_k256;
use super::KEM_KDF_VERSION;

/// ECDH KEM with secp256k1 curve
pub struct EcdhK256;

/// Public key for ECDH-K256 KEM (compressed EC point)
#[derive(Clone, Zeroize)]
pub struct EcdhK256PublicKey([u8; ec_k256::K256_POINT_COMPRESSED_SIZE]);

/// Secret key for ECDH-K256 KEM (scalar value)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhK256SecretKey(SecretBuffer<{ ec_k256::K256_SCALAR_SIZE }>);

/// Shared secret from ECDH-K256 KEM
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhK256SharedSecret(ApiKey);

/// Ciphertext for ECDH-K256 KEM (compressed ephemeral public key)
#[derive(Clone)]
pub struct EcdhK256Ciphertext([u8; ec_k256::K256_POINT_COMPRESSED_SIZE]);

// AsRef/AsMut implementations
impl AsRef<[u8]> for EcdhK256PublicKey { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for EcdhK256PublicKey { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }
impl AsRef<[u8]> for EcdhK256SecretKey { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl AsMut<[u8]> for EcdhK256SecretKey { fn as_mut(&mut self) -> &mut [u8] { self.0.as_mut() } }
impl AsRef<[u8]> for EcdhK256SharedSecret { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl AsMut<[u8]> for EcdhK256SharedSecret { fn as_mut(&mut self) -> &mut [u8] { self.0.as_mut() } }
impl AsRef<[u8]> for EcdhK256Ciphertext { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for EcdhK256Ciphertext { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }

impl Kem for EcdhK256 {
    type PublicKey = EcdhK256PublicKey;
    type SecretKey = EcdhK256SecretKey;
    type SharedSecret = EcdhK256SharedSecret;
    type Ciphertext = EcdhK256Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str { "ECDH-K256" }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) = ec_k256::generate_keypair(rng)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        let public_key = EcdhK256PublicKey(pk_point.serialize_compressed());
        let secret_key = EcdhK256SecretKey(sk_scalar.as_secret_buffer().clone());
        
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
        public_key_recipient: &Self::PublicKey,
    ) -> ApiResult<(Self::Ciphertext, Self::SharedSecret)> {
        // 1. Deserialize and validate recipient's public key (compressed format)
        let pk_r_point = ec_k256::Point::deserialize_compressed(&public_key_recipient.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        if pk_r_point.is_identity() {
            return Err(ApiError::InvalidKey { 
                context: "ECDH-K256 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key cannot be the identity point".to_string(),
            });
        }
    
        // 2. Generate ephemeral keypair for this encapsulation
        let (ephemeral_scalar, ephemeral_point) = ec_k256::generate_keypair(rng)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 3. Serialize ephemeral public key as the ciphertext (compressed format)
        let ciphertext = EcdhK256Ciphertext(ephemeral_point.serialize_compressed());
    
        // 4. Compute shared point: [ephemeral_scalar] * recipient_pk
        let shared_point = ec_k256::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 5. Check for identity point (which would lead to a weak key)
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed { 
                context: "ECDH-K256 encapsulate", 
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        
        // 6. Extract the x-coordinate for the KDF input
        let x_coord_bytes = shared_point.x_coordinate_bytes();
    
        // 7. Prepare KDF input: x-coordinate || ephemeral_pk || recipient_pk
        let mut kdf_ikm = Vec::with_capacity(
            ec_k256::K256_FIELD_ELEMENT_SIZE + 
            2 * ec_k256::K256_POINT_COMPRESSED_SIZE
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);
        
        // 8. Derive the shared secret with domain separation and version
        let info_string = format!("ECDH-K256-KEM {}", KEM_KDF_VERSION);
        let info = Some(info_string.as_bytes());
        let ss_bytes = ec_k256::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 9. Create the shared secret and ensure the ephemeral scalar is zeroized
        let shared_secret = EcdhK256SharedSecret(ApiKey::new(&ss_bytes));
        drop(ephemeral_scalar);
        
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key_recipient: &Self::SecretKey,
        ciphertext_ephemeral_pk: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        // 1. Create a Scalar from the secret key
        let sk_r_scalar = ec_k256::Scalar::from_secret_buffer(secret_key_recipient.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 2. Deserialize and validate the ephemeral public key from ciphertext (compressed format)
        let q_e_point = ec_k256::Point::deserialize_compressed(&ciphertext_ephemeral_pk.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext { 
                context: "ECDH-K256 decapsulate", 
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }

        // 3. Compute the shared point: [recipient_scalar] * ephemeral_pk
        let shared_point = ec_k256::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 4. Check for identity point
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed { 
                context: "ECDH-K256 decapsulate", 
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }

        // 5. Get the x-coordinate
        let x_coord_bytes = shared_point.x_coordinate_bytes();
        
        // 6. Compute the recipient's public key for KDF input
        let q_r_point = ec_k256::scalar_mult_base_g(&sk_r_scalar)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        // 7. Prepare KDF input with the same order as encapsulation
        let mut kdf_ikm = Vec::with_capacity(
            ec_k256::K256_FIELD_ELEMENT_SIZE + 
            2 * ec_k256::K256_POINT_COMPRESSED_SIZE
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        // 8. Derive the shared secret with same domain separation
        let info_string = format!("ECDH-K256-KEM {}", KEM_KDF_VERSION);
        let info = Some(info_string.as_bytes());
        let ss_bytes = ec_k256::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 9. Create and return the shared secret
        let shared_secret = EcdhK256SharedSecret(ApiKey::new(&ss_bytes));
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests;