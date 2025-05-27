// File: crates/kem/src/ecdh/p384.rs
//! ECDH-KEM with NIST P-384
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the 
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-384 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.

use api::{Kem, Result as ApiResult, Key as ApiKey, error::Error as ApiError};
use common::security::SecretBuffer;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{CryptoRng, RngCore};
use crate::error::{Error as KemError, Result as KemResult, validate as kem_validate};
use algorithms::ec::p384 as ec_p384;
use super::KEM_KDF_VERSION;

/// ECDH KEM with P-384 curve
pub struct EcdhP384;

/// Public key for ECDH-P384 KEM (compressed EC point)
#[derive(Clone, Zeroize)]
pub struct EcdhP384PublicKey([u8; ec_p384::P384_POINT_COMPRESSED_SIZE]);

/// Secret key for ECDH-P384 KEM (scalar value)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP384SecretKey(SecretBuffer<{ ec_p384::P384_SCALAR_SIZE }>);

/// Shared secret from ECDH-P384 KEM
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP384SharedSecret(ApiKey);

/// Ciphertext for ECDH-P384 KEM (compressed ephemeral public key)
#[derive(Clone)]
pub struct EcdhP384Ciphertext([u8; ec_p384::P384_POINT_COMPRESSED_SIZE]);

// AsRef/AsMut implementations
impl AsRef<[u8]> for EcdhP384PublicKey { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for EcdhP384PublicKey { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }
impl AsRef<[u8]> for EcdhP384SecretKey { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl AsMut<[u8]> for EcdhP384SecretKey { fn as_mut(&mut self) -> &mut [u8] { self.0.as_mut() } }
impl AsRef<[u8]> for EcdhP384SharedSecret { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl AsMut<[u8]> for EcdhP384SharedSecret { fn as_mut(&mut self) -> &mut [u8] { self.0.as_mut() } }
impl AsRef<[u8]> for EcdhP384Ciphertext { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for EcdhP384Ciphertext { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }

impl Kem for EcdhP384 {
    type PublicKey = EcdhP384PublicKey;
    type SecretKey = EcdhP384SecretKey;
    type SharedSecret = EcdhP384SharedSecret;
    type Ciphertext = EcdhP384Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str { "ECDH-P384" }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        // Generate a keypair using the EC implementation
        // The EC implementation already ensures proper scalar range and point validation
        let (sk_scalar, pk_point) = ec_p384::generate_keypair(rng)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Serialize the public key point using compressed format
        let public_key = EcdhP384PublicKey(pk_point.serialize_compressed());
        
        // Wrap the secret scalar in our type
        let secret_key = EcdhP384SecretKey(sk_scalar.as_secret_buffer().clone());
        
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
        let pk_r_point = ec_p384::Point::deserialize_compressed(&public_key_recipient.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Explicitly check for identity point (deserialize_compressed already does other validation)
        if pk_r_point.is_identity() {
            return Err(ApiError::InvalidKey { 
                context: "ECDH-P384 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key cannot be the identity point".to_string(),
            });
        }

        // 2. Generate ephemeral keypair for this encapsulation
        let (ephemeral_scalar, ephemeral_point) = ec_p384::generate_keypair(rng)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 3. Serialize ephemeral public key as the ciphertext (compressed format)
        let ciphertext = EcdhP384Ciphertext(ephemeral_point.serialize_compressed());

        // 4. Compute shared point: [ephemeral_scalar] * recipient_pk
        let shared_point = ec_p384::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 5. Check for identity point (which would lead to a weak key)
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed { 
                context: "ECDH-P384 encapsulate", 
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        
        // 6. Extract the x-coordinate for the KDF input
        let x_coord_bytes = shared_point.x_coordinate_bytes();

        // 7. Prepare KDF input: x-coordinate || ephemeral_pk || recipient_pk
        // This binding prevents the standard KDF inputs from being domain-separated
        let mut kdf_ikm = Vec::with_capacity(
            ec_p384::P384_FIELD_ELEMENT_SIZE + 
            2 * ec_p384::P384_POINT_COMPRESSED_SIZE  // Using compressed size
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);
        
        // 8. Derive the shared secret with domain separation and version
        let info_string = format!("ECDH-P384-KEM {}", KEM_KDF_VERSION);
        let info = Some(info_string.as_bytes());
        let ss_bytes = ec_p384::kdf_hkdf_sha384_for_ecdh_kem(&kdf_ikm, info.as_deref())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 9. Create the shared secret and ensure the ephemeral scalar is zeroized
        let shared_secret = EcdhP384SharedSecret(ApiKey::new(&ss_bytes));
        
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
        let scalar_result = ec_p384::Scalar::from_secret_buffer(secret_key_recipient.0.clone());
        let sk_r_scalar = match scalar_result {
            Ok(scalar) => scalar,
            Err(e) => return Err(ApiError::from(KemError::from(e))),
        };
        
        // 2. Deserialize and validate the ephemeral public key from ciphertext (compressed format)
        let q_e_point = ec_p384::Point::deserialize_compressed(&ciphertext_ephemeral_pk.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Check for identity point
        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext { 
                context: "ECDH-P384 decapsulate", 
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }

        // 3. Compute the shared point: [recipient_scalar] * ephemeral_pk
        let shared_point = ec_p384::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 4. Check for identity point
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed { 
                context: "ECDH-P384 decapsulate", 
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }

        // 5. Get the x-coordinate
        let x_coord_bytes = shared_point.x_coordinate_bytes();
        
        // 6. Compute the recipient's public key for KDF input
        let q_r_point = ec_p384::scalar_mult_base_g(&sk_r_scalar)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        // 7. Prepare KDF input with the same order as encapsulation
        let mut kdf_ikm = Vec::with_capacity(
            ec_p384::P384_FIELD_ELEMENT_SIZE + 
            2 * ec_p384::P384_POINT_COMPRESSED_SIZE  // Using compressed size
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        // 8. Derive the shared secret with same domain separation
        let info_string = format!("ECDH-P384-KEM {}", KEM_KDF_VERSION);
        let info = Some(info_string.as_bytes());
        let ss_bytes = ec_p384::kdf_hkdf_sha384_for_ecdh_kem(&kdf_ikm, info.as_deref())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // 9. Create and return the shared secret
        let shared_secret = EcdhP384SharedSecret(ApiKey::new(&ss_bytes));
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests;