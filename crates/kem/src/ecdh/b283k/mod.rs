// File: crates/kem/src/ecdh/b283k/mod.rs
//! ECDH-KEM with sect283k1 (B-283k)
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the SECG binary curve sect283k1.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.
//! 
//! # Security Features
//! 
//! - No direct byte access to keys (prevents tampering and accidental exposure)
//! - Constant-time operations where applicable
//! - Proper validation of curve points
//! - Secure key derivation using HKDF-SHA384

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::b283k as ec_b283k;
use dcrypt_api::{error::Error as ApiError, Kem, Key as ApiKey, Result as ApiResult};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ECDH KEM with sect283k1 curve
pub struct EcdhB283k;

/// Public key for ECDH-B283k KEM (compressed EC point)
#[derive(Clone, Zeroize)]
pub struct EcdhB283kPublicKey([u8; ec_b283k::B283K_POINT_COMPRESSED_SIZE]);

/// Secret key for ECDH-B283k KEM (scalar value)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhB283kSecretKey(SecretBuffer<{ ec_b283k::B283K_SCALAR_SIZE }>);

/// Shared secret from ECDH-B283k KEM
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhB283kSharedSecret(ApiKey);

/// Ciphertext for ECDH-B283k KEM (compressed ephemeral public key)
#[derive(Clone)]
pub struct EcdhB283kCiphertext([u8; ec_b283k::B283K_POINT_COMPRESSED_SIZE]);

// Public key methods
impl EcdhB283kPublicKey {
    /// Create a public key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed point representation (37 bytes for B-283k)
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
        if bytes.len() != ec_b283k::B283K_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhB283kPublicKey::from_bytes",
                expected: ec_b283k::B283K_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec_b283k::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhB283kPublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the key
        let mut key_bytes = [0u8; ec_b283k::B283K_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }
    
    /// Export the public key to bytes
    /// 
    /// # Returns
    /// The compressed point representation (37 bytes for B-283k)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Secret key methods
impl EcdhB283kSecretKey {
    /// Create a secret key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The scalar value (36 bytes for B-283k)
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
        if bytes.len() != ec_b283k::B283K_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhB283kSecretKey::from_bytes",
                expected: ec_b283k::B283K_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Create a secret buffer from the bytes
        let mut buffer_bytes = [0u8; ec_b283k::B283K_SCALAR_SIZE];
        buffer_bytes.copy_from_slice(bytes);
        let buffer = SecretBuffer::new(buffer_bytes);
        
        // Validate the scalar is in valid range [1, n-1]
        let scalar = ec_b283k::Scalar::from_secret_buffer(buffer.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // The scalar is valid, so we can use the buffer
        drop(scalar); // Explicitly drop to ensure zeroization
        Ok(Self(buffer))
    }
    
    /// Export the secret key to bytes (with zeroization on drop)
    /// 
    /// # Returns
    /// The scalar value wrapped in `Zeroizing` (36 bytes for B-283k)
    /// 
    /// # Security
    /// The returned value will be automatically zeroized when dropped.
    /// Handle with care and minimize the lifetime of the returned value.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

// Shared secret methods
impl EcdhB283kSharedSecret {
    /// Export the shared secret to bytes
    /// 
    /// # Returns
    /// The derived shared secret bytes (48 bytes for B-283k with SHA-384)
    /// 
    /// # Security Note
    /// The shared secret should be used immediately for key derivation
    /// and not stored long-term.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}

// Ciphertext methods
impl EcdhB283kCiphertext {
    /// Create a ciphertext from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed ephemeral public key (37 bytes for B-283k)
    /// 
    /// # Returns
    /// * `Ok(Ciphertext)` if the bytes represent a valid ephemeral key
    /// * `Err` if the bytes are invalid
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec_b283k::B283K_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhB283kCiphertext::from_bytes",
                expected: ec_b283k::B283K_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec_b283k::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhB283kCiphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the ciphertext
        let mut ct_bytes = [0u8; ec_b283k::B283K_POINT_COMPRESSED_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    
    /// Export the ciphertext to bytes
    /// 
    /// # Returns
    /// The compressed ephemeral public key (37 bytes for B-283k)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// NO AsRef<[u8]> or AsMut<[u8]> implementations for security
// Direct byte access is prevented to avoid:
// - Key tampering (no AsMut)
// - Accidental key exposure (no AsRef)
// All byte access must go through explicit to_bytes()/from_bytes() methods

impl Kem for EcdhB283k {
    type PublicKey = EcdhB283kPublicKey;
    type SecretKey = EcdhB283kSecretKey;
    type SharedSecret = EcdhB283kSharedSecret;
    type Ciphertext = EcdhB283kCiphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-B283k"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) =
            ec_b283k::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;

        let public_key = EcdhB283kPublicKey(pk_point.serialize_compressed());
        let secret_key = EcdhB283kSecretKey(sk_scalar.as_secret_buffer().clone());

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
        let pk_r_point = ec_b283k::Point::deserialize_compressed(&public_key_recipient.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        if pk_r_point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "ECDH-B283k encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key cannot be the identity point".to_string(),
            });
        }

        let (ephemeral_scalar, ephemeral_point) =
            ec_b283k::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;

        let ciphertext = EcdhB283kCiphertext(ephemeral_point.serialize_compressed());

        let shared_point = ec_b283k::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-B283k encapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }

        let x_coord_bytes = shared_point.x_coordinate_bytes();

        let mut kdf_ikm = Vec::with_capacity(
            ec_b283k::B283K_FIELD_ELEMENT_SIZE + 2 * ec_b283k::B283K_POINT_COMPRESSED_SIZE,
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);

        let info: Option<&[u8]> = Some(b"ECDH-B283k-KEM");
        let ss_bytes = ec_b283k::kdf_hkdf_sha384_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let shared_secret = EcdhB283kSharedSecret(ApiKey::new(&ss_bytes));
        drop(ephemeral_scalar);

        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key_recipient: &Self::SecretKey,
        ciphertext_ephemeral_pk: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        let sk_r_scalar = ec_b283k::Scalar::from_secret_buffer(secret_key_recipient.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let q_e_point = ec_b283k::Point::deserialize_compressed(&ciphertext_ephemeral_pk.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "ECDH-B283k decapsulate",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }

        let shared_point = ec_b283k::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-B283k decapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }

        let x_coord_bytes = shared_point.x_coordinate_bytes();

        let q_r_point = ec_b283k::scalar_mult_base_g(&sk_r_scalar)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let mut kdf_ikm = Vec::with_capacity(
            ec_b283k::B283K_FIELD_ELEMENT_SIZE + 2 * ec_b283k::B283K_POINT_COMPRESSED_SIZE,
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        let info: Option<&[u8]> = Some(b"ECDH-B283k-KEM");
        let ss_bytes = ec_b283k::kdf_hkdf_sha384_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let shared_secret = EcdhB283kSharedSecret(ApiKey::new(&ss_bytes));
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests;