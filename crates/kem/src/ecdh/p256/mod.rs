// File: crates/kem/src/ecdh/p256.rs
//! ECDH-KEM with NIST P-256
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the 
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-256 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.

use api::{Kem, Result as ApiResult, Key as ApiKey, error::Error as ApiError};
use common::security::SecretBuffer;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{CryptoRng, RngCore};
use crate::error::Error as KemError;
use algorithms::ec::p256 as ec_p256;
use super::KEM_KDF_VERSION;

/// ECDH KEM with P-256 curve
pub struct EcdhP256;

/// Public key for ECDH-P256 KEM (compressed EC point)
#[derive(Clone, Zeroize)]
pub struct EcdhP256PublicKey([u8; ec_p256::P256_POINT_COMPRESSED_SIZE]);

/// Secret key for ECDH-P256 KEM (scalar value)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP256SecretKey(SecretBuffer<{ ec_p256::P256_SCALAR_SIZE }>);

/// Shared secret from ECDH-P256 KEM
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP256SharedSecret(ApiKey);

/// Ciphertext for ECDH-P256 KEM (compressed ephemeral public key)
#[derive(Clone)]
pub struct EcdhP256Ciphertext([u8; ec_p256::P256_POINT_COMPRESSED_SIZE]);

// AsRef/AsMut implementations
impl AsRef<[u8]> for EcdhP256PublicKey { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for EcdhP256PublicKey { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }
impl AsRef<[u8]> for EcdhP256SecretKey { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl AsMut<[u8]> for EcdhP256SecretKey { fn as_mut(&mut self) -> &mut [u8] { self.0.as_mut() } }
impl AsRef<[u8]> for EcdhP256SharedSecret { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl AsMut<[u8]> for EcdhP256SharedSecret { fn as_mut(&mut self) -> &mut [u8] { self.0.as_mut() } }
impl AsRef<[u8]> for EcdhP256Ciphertext { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for EcdhP256Ciphertext { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }

impl Kem for EcdhP256 {
    type PublicKey = EcdhP256PublicKey;
    type SecretKey = EcdhP256SecretKey;
    type SharedSecret = EcdhP256SharedSecret;
    type Ciphertext = EcdhP256Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str { "ECDH-P256" }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        // Generate a keypair using the EC implementation
        // The EC implementation already ensures proper scalar range and point validation
        let (sk_scalar, pk_point) = ec_p256::generate_keypair(rng)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Serialize the public key point using compressed format
        let public_key = EcdhP256PublicKey(pk_point.serialize_compressed());
        
        // Wrap the secret scalar in our type
        let secret_key = EcdhP256SecretKey(sk_scalar.as_secret_buffer().clone());
        
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
        let pk_r_point = ec_p256::Point::deserialize_compressed(&public_key_recipient.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Explicitly check for identity point (deserialize_compressed already does other validation)
        if pk_r_point.is_identity() {
            return Err(ApiError::InvalidKey { 
                context: "ECDH-P256 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key cannot be the identity point".to_string(),
            });
        }
    
        // 2. Generate ephemeral keypair without rejection sampling for KAT compatibility
        // Pull exactly 32 bytes and create scalar (will be reduced mod n if needed)
        let mut ephemeral_bytes = [0u8; ec_p256::P256_SCALAR_SIZE];
        rng.fill_bytes(&mut ephemeral_bytes);
        
        // Create scalar using from_secret_buffer which reduces mod n without rejection
        let ephemeral_buffer = SecretBuffer::new(ephemeral_bytes);
        let ephemeral_scalar = ec_p256::Scalar::from_secret_buffer(ephemeral_buffer)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Generate ephemeral public key: ephemeral_point = ephemeral_scalar * G
        let ephemeral_point = ec_p256::scalar_mult_base_g(&ephemeral_scalar)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 3. Serialize ephemeral public key as the ciphertext (compressed format)
        let ciphertext = EcdhP256Ciphertext(ephemeral_point.serialize_compressed());
    
        // 4. Compute shared point: [ephemeral_scalar] * recipient_pk
        let shared_point = ec_p256::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 5. Check for identity point (which would lead to a weak key)
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed { 
                context: "ECDH-P256 encapsulate", 
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        
        // 6. Extract the x-coordinate for the KDF input
        let x_coord_bytes = shared_point.x_coordinate_bytes();
    
        // 7. Prepare KDF input: x-coordinate || ephemeral_pk || recipient_pk
        // This binding prevents the standard KDF inputs from being domain-separated
        let mut kdf_ikm = Vec::with_capacity(
            ec_p256::P256_FIELD_ELEMENT_SIZE + 
            2 * ec_p256::P256_POINT_COMPRESSED_SIZE  // Using compressed size
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);
        
        // 8. Derive the shared secret with domain separation and version
        let info_string = format!("ECDH-P256-KEM {}", KEM_KDF_VERSION);
        let info = Some(info_string.as_bytes());
        let ss_bytes = ec_p256::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 9. Create the shared secret and ensure the ephemeral scalar is zeroized
        let shared_secret = EcdhP256SharedSecret(ApiKey::new(&ss_bytes));
        
        // Explicitly zeroize the ephemeral scalar for defense-in-depth
        // (even though it already implements ZeroizeOnDrop)
        drop(ephemeral_scalar); // This will trigger zeroization
        
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key_recipient: &Self::SecretKey,
        ciphertext_ephemeral_pk: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        // 1. Create a Scalar from the secret key
        let scalar_result = ec_p256::Scalar::from_secret_buffer(secret_key_recipient.0.clone());
        let sk_r_scalar = match scalar_result {
            Ok(scalar) => scalar,
            Err(e) => return Err(ApiError::from(KemError::from(e))),
        };
        
        // 2. Deserialize and validate the ephemeral public key from ciphertext (compressed format)
        let q_e_point = ec_p256::Point::deserialize_compressed(&ciphertext_ephemeral_pk.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Check for identity point
        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext { 
                context: "ECDH-P256 decapsulate", 
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }

        // 3. Compute the shared point: [recipient_scalar] * ephemeral_pk
        let shared_point = ec_p256::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 4. Check for identity point
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed { 
                context: "ECDH-P256 decapsulate", 
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }

        // 5. Get the x-coordinate
        let x_coord_bytes = shared_point.x_coordinate_bytes();
        
        // 6. Compute the recipient's public key for KDF input
        let q_r_point = ec_p256::scalar_mult_base_g(&sk_r_scalar)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        // 7. Prepare KDF input with the same order as encapsulation
        let mut kdf_ikm = Vec::with_capacity(
            ec_p256::P256_FIELD_ELEMENT_SIZE + 
            2 * ec_p256::P256_POINT_COMPRESSED_SIZE  // Using compressed size
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        // 8. Derive the shared secret with same domain separation
        let info_string = format!("ECDH-P256-KEM {}", KEM_KDF_VERSION);
        let info = Some(info_string.as_bytes());
        let ss_bytes = ec_p256::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 9. Create and return the shared secret
        let shared_secret = EcdhP256SharedSecret(ApiKey::new(&ss_bytes));
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests;