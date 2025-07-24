// File: crates/kem/src/ecdh/p224.rs
//! ECDH-KEM with NIST P-224
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-224 curve.
//! Uses HKDF-SHA256 for key derivation and compressed points for ciphertexts.
//! Includes authentication via HMAC-SHA256 tags to ensure key confirmation.

use dcrypt_api::{Kem, Result as ApiResult, Key as ApiKey, error::Error as ApiError};
use dcrypt_common::security::SecretBuffer;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{CryptoRng, RngCore};
use crate::error::Error as KemError;
use dcrypt_algorithms::ec::p224 as ec; // Use P-224 algorithms
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_algorithms::hash::sha2::Sha256;
use super::KEM_KDF_VERSION; // KDF version from parent ecdh module

/// ECDH KEM with P-224 curve
pub struct EcdhP224;

/// Public key for ECDH-P224 KEM (compressed EC point)
#[derive(Clone, Zeroize)]
pub struct EcdhP224PublicKey([u8; ec::P224_POINT_COMPRESSED_SIZE]);

/// Secret key for ECDH-P224 KEM (scalar value)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP224SecretKey(SecretBuffer<{ ec::P224_SCALAR_SIZE }>);

/// Shared secret from ECDH-P224 KEM
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP224SharedSecret(ApiKey);

/// Ciphertext for ECDH-P224 KEM (compressed ephemeral public key + authentication tag)
#[derive(Clone)]
pub struct EcdhP224Ciphertext([u8; ec::P224_CIPHERTEXT_SIZE]);

// AsRef/AsMut implementations
impl AsRef<[u8]> for EcdhP224PublicKey { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for EcdhP224PublicKey { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }
impl AsRef<[u8]> for EcdhP224SecretKey { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl AsMut<[u8]> for EcdhP224SecretKey { fn as_mut(&mut self) -> &mut [u8] { self.0.as_mut() } }
impl AsRef<[u8]> for EcdhP224SharedSecret { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl AsMut<[u8]> for EcdhP224SharedSecret { fn as_mut(&mut self) -> &mut [u8] { self.0.as_mut() } }
impl AsRef<[u8]> for EcdhP224Ciphertext { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for EcdhP224Ciphertext { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }

/// Calculate authentication tag for key confirmation
/// 
/// Uses truncated HMAC-SHA256 to create a 16-byte tag that proves
/// the sender and receiver computed the same shared secret.
fn calc_auth_tag(shared_secret: &[u8]) -> Result<[u8; ec::P224_TAG_SIZE], KemError> {
    // Create HMAC-SHA256 instance with fixed key
    let mut hmac = Hmac::<Sha256>::new(b"ECDH-P224-KEM tag")
        .map_err(KemError::from)?;
    
    // Update with shared secret
    hmac.update(shared_secret)
        .map_err(KemError::from)?;
    
    // Finalize and get tag (SHA256 produces 32-byte tags)
    let tag_vec: Vec<u8> = hmac.finalize()
        .map_err(KemError::from)?;
    
    // Truncate to P224_TAG_SIZE bytes
    let mut truncated = [0u8; ec::P224_TAG_SIZE];
    truncated.copy_from_slice(&tag_vec[..ec::P224_TAG_SIZE]);
    Ok(truncated)
}

impl Kem for EcdhP224 {
    type PublicKey = EcdhP224PublicKey;
    type SecretKey = EcdhP224SecretKey;
    type SharedSecret = EcdhP224SharedSecret;
    type Ciphertext = EcdhP224Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str { "ECDH-P224" }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) = ec::generate_keypair(rng)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let public_key = EcdhP224PublicKey(pk_point.serialize_compressed());
        let secret_key = EcdhP224SecretKey(sk_scalar.as_secret_buffer().clone());
        Ok((public_key, secret_key))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey { keypair.0.clone() }
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey { keypair.1.clone() }

    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key_recipient: &Self::PublicKey,
    ) -> ApiResult<(Self::Ciphertext, Self::SharedSecret)> {
        let pk_r_point = ec::Point::deserialize_compressed(&public_key_recipient.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if pk_r_point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "ECDH-P224 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key is identity".to_string(),
            });
        }

        let (ephemeral_scalar, ephemeral_point) = ec::generate_keypair(rng)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let ephemeral_pk_compressed = ephemeral_point.serialize_compressed();

        let shared_point = ec::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P224 encapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is identity".to_string(),
            });
        }
        let x_coord_bytes = shared_point.x_coordinate_bytes();

        let mut kdf_ikm = Vec::with_capacity(
            ec::P224_FIELD_ELEMENT_SIZE + 2 * ec::P224_POINT_COMPRESSED_SIZE
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_pk_compressed);
        kdf_ikm.extend_from_slice(&public_key_recipient.0);

        let info_string = format!("ECDH-P224-KEM {}", KEM_KDF_VERSION);
        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(info_string.as_bytes()))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let shared_secret = EcdhP224SharedSecret(ApiKey::new(&ss_bytes));

        // Create authenticated ciphertext: ephemeral_pk || tag
        let mut ct_bytes = [0u8; ec::P224_CIPHERTEXT_SIZE];
        ct_bytes[..ec::P224_POINT_COMPRESSED_SIZE].copy_from_slice(&ephemeral_pk_compressed);
        let tag = calc_auth_tag(&ss_bytes)
            .map_err(ApiError::from)?;
        ct_bytes[ec::P224_POINT_COMPRESSED_SIZE..].copy_from_slice(&tag);
        let ciphertext = EcdhP224Ciphertext(ct_bytes);

        drop(ephemeral_scalar);
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key_recipient: &Self::SecretKey,
        ciphertext_ephemeral_pk: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        // Split ciphertext into ephemeral public key and tag
        let (pk_bytes, tag_bytes) = ciphertext_ephemeral_pk.0
            .split_at(ec::P224_POINT_COMPRESSED_SIZE);
        
        // Convert tag bytes to array for comparison
        let mut received_tag = [0u8; ec::P224_TAG_SIZE];
        received_tag.copy_from_slice(tag_bytes);

        let sk_r_scalar = ec::Scalar::from_secret_buffer(secret_key_recipient.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let q_e_point = ec::Point::deserialize_compressed(pk_bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "ECDH-P224 decapsulate",
                #[cfg(feature = "std")]
                message: "Ephemeral PK is identity".to_string(),
            });
        }

        let shared_point = ec::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P224 decapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is identity".to_string(),
            });
        }
        let x_coord_bytes = shared_point.x_coordinate_bytes();
        let q_r_point = ec::scalar_mult_base_g(&sk_r_scalar)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let mut kdf_ikm = Vec::with_capacity(
            ec::P224_FIELD_ELEMENT_SIZE + 2 * ec::P224_POINT_COMPRESSED_SIZE
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(pk_bytes); // Use only the PK part, not the full ciphertext
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        let info_string = format!("ECDH-P224-KEM {}", KEM_KDF_VERSION);
        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(info_string.as_bytes()))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        // Verify authentication tag
        let expected_tag = calc_auth_tag(&ss_bytes)
            .map_err(ApiError::from)?;
        
        // Constant-time comparison of tags (array to array)
        use dcrypt_common::security::SecureCompare;
        if !received_tag.secure_eq(&expected_tag) {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P224 decapsulate",
                #[cfg(feature = "std")]
                message: "Authentication tag mismatch".to_string(),
            });
        }

        Ok(EcdhP224SharedSecret(ApiKey::new(&ss_bytes)))
    }
}

#[cfg(test)]
mod tests; 