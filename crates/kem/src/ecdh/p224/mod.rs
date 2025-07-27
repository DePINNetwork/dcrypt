// File: crates/kem/src/ecdh/p224/mod.rs
//! ECDH-KEM with NIST P-224
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-224 curve.
//! Uses HKDF-SHA256 for key derivation and compressed points for ciphertexts.
//! Includes authentication via HMAC-SHA256 tags to ensure key confirmation.
//!
//! # Security Features
//! 
//! - No mutable access to keys or secrets (prevents tampering)
//! - No direct byte access (prevents accidental exposure)
//! - Authentication tags prevent ciphertext substitution attacks
//! - Constant-time operations where applicable
//! - Proper validation of curve points

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::p224 as ec; // Use P-224 algorithms
use dcrypt_algorithms::hash::sha2::Sha256;
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_api::{error::Error as ApiError, Kem, Key as ApiKey, Result as ApiResult};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

// Public key methods
impl EcdhP224PublicKey {
    /// Create a public key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed point representation (29 bytes for P-224)
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
        if bytes.len() != ec::P224_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP224PublicKey::from_bytes",
                expected: ec::P224_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhP224PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the key
        let mut key_bytes = [0u8; ec::P224_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }
    
    /// Export the public key to bytes
    /// 
    /// # Returns
    /// The compressed point representation (29 bytes for P-224)
    /// 
    /// # Security Note
    /// Public keys are not secret and can be shared freely.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    
    /// Validate this public key
    /// 
    /// # Returns
    /// * `Ok(())` if the key is valid
    /// * `Err` if the key is invalid (identity point or not on curve)
    pub fn validate(&self) -> ApiResult<()> {
        // Re-validate by attempting to deserialize
        let point = ec::Point::deserialize_compressed(&self.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "validate_public_key",
                #[cfg(feature = "std")]
                message: "Public key is the identity point".to_string(),
            });
        }
        
        Ok(())
    }
}

// Secret key methods
impl EcdhP224SecretKey {
    /// Create a secret key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The scalar value (28 bytes for P-224)
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
        if bytes.len() != ec::P224_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP224SecretKey::from_bytes",
                expected: ec::P224_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Create a secret buffer from the bytes
        let mut buffer_bytes = [0u8; ec::P224_SCALAR_SIZE];
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
    /// The scalar value wrapped in `Zeroizing` (28 bytes for P-224)
    /// 
    /// # Security
    /// The returned value will be automatically zeroized when dropped.
    /// Handle with care and minimize the lifetime of the returned value.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
    
    /// Validate this secret key
    /// 
    /// # Returns
    /// * `Ok(())` if the key is valid
    /// * `Err` if the key is invalid (zero or out of range)
    pub fn validate(&self) -> ApiResult<()> {
        // Validation happens during scalar creation
        let _ = ec::Scalar::from_secret_buffer(self.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        Ok(())
    }
}

// Shared secret methods
impl EcdhP224SharedSecret {
    /// Export the shared secret to bytes
    /// 
    /// # Returns
    /// The derived shared secret bytes
    /// 
    /// # Security Note
    /// The shared secret should be used immediately for key derivation
    /// and not stored long-term. Consider using a KDF to derive
    /// application-specific keys.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

// Ciphertext methods
impl EcdhP224Ciphertext {
    /// Create a ciphertext from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The authenticated ciphertext (45 bytes for P-224: 29 bytes compressed point + 16 bytes tag)
    /// 
    /// # Returns
    /// * `Ok(Ciphertext)` if the bytes represent a valid authenticated ciphertext
    /// * `Err` if the bytes are invalid
    /// 
    /// # Security Note
    /// The authentication tag is verified during decapsulation, not here.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec::P224_CIPHERTEXT_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP224Ciphertext::from_bytes",
                expected: ec::P224_CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate the ephemeral public key part
        let pk_bytes = &bytes[..ec::P224_POINT_COMPRESSED_SIZE];
        let point = ec::Point::deserialize_compressed(pk_bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhP224Ciphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the ciphertext (includes both ephemeral key and tag)
        let mut ct_bytes = [0u8; ec::P224_CIPHERTEXT_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    
    /// Export the ciphertext to bytes
    /// 
    /// # Returns
    /// The authenticated ciphertext (45 bytes for P-224: compressed ephemeral public key + tag)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    
    /// Validate this ciphertext
    /// 
    /// # Returns
    /// * `Ok(())` if the ciphertext format is valid
    /// * `Err` if the ciphertext is invalid
    /// 
    /// # Note
    /// This only validates the format. Authentication tag verification happens during decapsulation.
    pub fn validate(&self) -> ApiResult<()> {
        // Validate the ephemeral public key part
        let pk_bytes = &self.0[..ec::P224_POINT_COMPRESSED_SIZE];
        let point = ec::Point::deserialize_compressed(pk_bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "validate_ciphertext",
                #[cfg(feature = "std")]
                message: "Ciphertext contains identity point".to_string(),
            });
        }
        
        // Note: We don't validate the tag here - that happens during decapsulation
        Ok(())
    }
}

/// Calculate authentication tag for key confirmation
///
/// Uses truncated HMAC-SHA256 to create a 16-byte tag that proves
/// the sender and receiver computed the same shared secret.
fn calc_auth_tag(shared_secret: &[u8]) -> Result<[u8; ec::P224_TAG_SIZE], KemError> {
    // Create HMAC-SHA256 instance with fixed key
    let mut hmac = Hmac::<Sha256>::new(b"ECDH-P224-KEM tag").map_err(KemError::from)?;

    // Update with shared secret
    hmac.update(shared_secret).map_err(KemError::from)?;

    // Finalize and get tag (SHA256 produces 32-byte tags)
    let tag_vec: Vec<u8> = hmac.finalize().map_err(KemError::from)?;

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

    fn name() -> &'static str {
        "ECDH-P224"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let public_key = EcdhP224PublicKey(pk_point.serialize_compressed());
        let secret_key = EcdhP224SecretKey(sk_scalar.as_secret_buffer().clone());
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
                context: "ECDH-P224 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key is identity".to_string(),
            });
        }

        let (ephemeral_scalar, ephemeral_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
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

        let mut kdf_ikm =
            Vec::with_capacity(ec::P224_FIELD_ELEMENT_SIZE + 2 * ec::P224_POINT_COMPRESSED_SIZE);
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_pk_compressed);
        kdf_ikm.extend_from_slice(&public_key_recipient.0);

        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(&b"ECDH-P224-KEM"[..]))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let shared_secret = EcdhP224SharedSecret(ApiKey::new(&ss_bytes));

        // Create authenticated ciphertext: ephemeral_pk || tag
        let mut ct_bytes = [0u8; ec::P224_CIPHERTEXT_SIZE];
        ct_bytes[..ec::P224_POINT_COMPRESSED_SIZE].copy_from_slice(&ephemeral_pk_compressed);
        let tag = calc_auth_tag(&ss_bytes).map_err(ApiError::from)?;
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
        let (pk_bytes, tag_bytes) = ciphertext_ephemeral_pk
            .0
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
        let q_r_point =
            ec::scalar_mult_base_g(&sk_r_scalar).map_err(|e| ApiError::from(KemError::from(e)))?;

        let mut kdf_ikm =
            Vec::with_capacity(ec::P224_FIELD_ELEMENT_SIZE + 2 * ec::P224_POINT_COMPRESSED_SIZE);
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(pk_bytes); // Use only the PK part, not the full ciphertext
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(&b"ECDH-P224-KEM"[..]))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        // Verify authentication tag
        let expected_tag = calc_auth_tag(&ss_bytes).map_err(ApiError::from)?;

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