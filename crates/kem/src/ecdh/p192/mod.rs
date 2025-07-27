// File: crates/kem/src/ecdh/p192/mod.rs
//! ECDH-KEM with NIST P-192
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-192 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//! This implementation uses compressed point format.
//!
//! # Security Features
//! 
//! - No direct byte access to keys (prevents tampering and leakage)
//! - Constant-time operations where applicable
//! - Proper validation of curve points
//! - Secure key derivation using HKDF-SHA256

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::p192 as ec;
use dcrypt_api::{error::Error as ApiError, Kem, Key as ApiKey, Result as ApiResult};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ECDH KEM with P-192 curve
pub struct EcdhP192;

/// Public key for ECDH-P192 KEM (compressed EC point)
/// 
/// # Security Note
/// This type provides no direct byte access. Use the `to_bytes()` method
/// for serialization and `from_bytes()` for deserialization.
#[derive(Clone, Zeroize)]
pub struct EcdhP192PublicKey([u8; ec::P192_POINT_COMPRESSED_SIZE]);

/// Secret key for ECDH-P192 KEM (scalar value)
/// 
/// # Security Note
/// This type provides no direct byte access to prevent key exposure.
/// Use the `to_bytes()` method which returns a `Zeroizing` wrapper.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP192SecretKey(SecretBuffer<{ ec::P192_SCALAR_SIZE }>);

/// Shared secret from ECDH-P192 KEM
/// 
/// # Security Note
/// This type provides no direct byte access to prevent secret leakage.
/// Convert to application keys immediately after generation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP192SharedSecret(ApiKey);

/// Ciphertext for ECDH-P192 KEM (compressed ephemeral public key)
/// 
/// # Security Note
/// This type provides no direct byte access to prevent tampering.
#[derive(Clone)]
pub struct EcdhP192Ciphertext([u8; ec::P192_POINT_COMPRESSED_SIZE]);

// Public key methods
impl EcdhP192PublicKey {
    /// Create a public key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed point representation (25 bytes for P-192)
    /// 
    /// # Returns
    /// * `Ok(PublicKey)` if the bytes represent a valid point on the curve
    /// * `Err` if the bytes are invalid (wrong length, invalid point, or identity)
    /// 
    /// # Security Note
    /// This method validates that the point is on the curve and not the identity,
    /// preventing invalid key attacks.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec::P192_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP192PublicKey::from_bytes",
                expected: ec::P192_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhP192PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the key
        let mut key_bytes = [0u8; ec::P192_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }
    
    /// Export the public key to bytes
    /// 
    /// # Returns
    /// The compressed point representation (25 bytes for P-192)
    /// 
    /// # Security Note
    /// Public keys are not secret and can be shared freely.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Secret key methods
impl EcdhP192SecretKey {
    /// Create a secret key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The scalar value (24 bytes for P-192)
    /// 
    /// # Returns
    /// * `Ok(SecretKey)` if the bytes represent a valid scalar
    /// * `Err` if the bytes are invalid (wrong length or out of range)
    /// 
    /// # Security
    /// The input bytes should be treated as sensitive material and zeroized after use.
    /// This method validates that the scalar is in the valid range [1, n-1].
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec::P192_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP192SecretKey::from_bytes",
                expected: ec::P192_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Create a secret buffer from the bytes
        let mut buffer_bytes = [0u8; ec::P192_SCALAR_SIZE];
        buffer_bytes.copy_from_slice(bytes);
        let buffer = SecretBuffer::new(buffer_bytes);
        
        // Validate the scalar is in valid range [1, n-1]
        let scalar = ec::Scalar::from_secret_buffer(buffer.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // The scalar is valid, so we can use the buffer
        drop(scalar); // Explicitly drop to ensure zeroization
        Ok(Self(buffer))
    }
    
    /// Export the secret key to bytes (with zeroization on drop)
    /// 
    /// # Returns
    /// The scalar value wrapped in `Zeroizing` (24 bytes for P-192)
    /// 
    /// # Security
    /// The returned value will be automatically zeroized when dropped.
    /// Handle with care and minimize the lifetime of the returned value.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

// Shared secret methods
impl EcdhP192SharedSecret {
    /// Export the shared secret to bytes
    /// 
    /// # Returns
    /// The derived shared secret bytes
    /// 
    /// # Security Note
    /// The shared secret should be used immediately for key derivation
    /// and not stored long-term. Consider wrapping in `Zeroizing` if needed.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
    
    /// Export the shared secret to bytes with zeroization
    /// 
    /// # Returns
    /// The derived shared secret bytes wrapped in `Zeroizing`
    /// 
    /// # Security Note
    /// Use this method when you need automatic cleanup of the secret bytes.
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

// Ciphertext methods
impl EcdhP192Ciphertext {
    /// Create a ciphertext from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed ephemeral public key (25 bytes for P-192)
    /// 
    /// # Returns
    /// * `Ok(Ciphertext)` if the bytes represent a valid ephemeral key
    /// * `Err` if the bytes are invalid
    /// 
    /// # Security Note
    /// Validates that the ephemeral key is a valid curve point.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec::P192_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP192Ciphertext::from_bytes",
                expected: ec::P192_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhP192Ciphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the ciphertext
        let mut ct_bytes = [0u8; ec::P192_POINT_COMPRESSED_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    
    /// Export the ciphertext to bytes
    /// 
    /// # Returns
    /// The compressed ephemeral public key (25 bytes for P-192)
    /// 
    /// # Security Note
    /// Ciphertexts are public data and can be transmitted over insecure channels.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// No AsRef or AsMut implementations - this prevents direct byte access

impl Kem for EcdhP192 {
    type PublicKey = EcdhP192PublicKey;
    type SecretKey = EcdhP192SecretKey;
    type SharedSecret = EcdhP192SharedSecret;
    type Ciphertext = EcdhP192Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P192"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let public_key = EcdhP192PublicKey(pk_point.serialize_compressed());
        let secret_key = EcdhP192SecretKey(sk_scalar.as_secret_buffer().clone());
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
        let pk_r_point = ec::Point::deserialize_compressed(&public_key_recipient.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if pk_r_point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "ECDH-P192 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key is identity".to_string(),
            });
        }

        let (ephemeral_scalar, ephemeral_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let ciphertext = EcdhP192Ciphertext(ephemeral_point.serialize_compressed());

        let shared_point = ec::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P192 encapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        let x_coord_bytes = shared_point.x_coordinate_bytes();

        let mut kdf_ikm =
            Vec::with_capacity(ec::P192_FIELD_ELEMENT_SIZE + 2 * ec::P192_POINT_COMPRESSED_SIZE);
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);

        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(&b"ECDH-P192-KEM"[..]))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let shared_secret = EcdhP192SharedSecret(ApiKey::new(&ss_bytes));
        drop(ephemeral_scalar);
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key_recipient: &Self::SecretKey,
        ciphertext_ephemeral_pk: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        let sk_r_scalar = ec::Scalar::from_secret_buffer(secret_key_recipient.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let q_e_point = ec::Point::deserialize_compressed(&ciphertext_ephemeral_pk.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "ECDH-P192 decapsulate",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }

        let shared_point = ec::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P192 decapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        let x_coord_bytes = shared_point.x_coordinate_bytes();
        let q_r_point =
            ec::scalar_mult_base_g(&sk_r_scalar).map_err(|e| ApiError::from(KemError::from(e)))?;

        let mut kdf_ikm =
            Vec::with_capacity(ec::P192_FIELD_ELEMENT_SIZE + 2 * ec::P192_POINT_COMPRESSED_SIZE);
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(&b"ECDH-P192-KEM"[..]))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        Ok(EcdhP192SharedSecret(ApiKey::new(&ss_bytes)))
    }
}

#[cfg(test)]
mod tests;