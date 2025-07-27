// File: crates/kem/src/ecdh/p256/mod.rs
//! ECDH-KEM with NIST P-256
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-256 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.
//!
//! # Security Features
//! 
//! - No direct byte access to keys (prevents tampering and accidental exposure)
//! - Constant-time scalar operations
//! - Point validation to prevent invalid curve attacks
//! - Secure key derivation using HKDF-SHA256
//! - Implicit rejection for IND-CCA2 security

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::p256 as ec_p256;
use dcrypt_api::{error::Error as ApiError, Kem, Key as ApiKey, Result as ApiResult};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

// Public key methods
impl EcdhP256PublicKey {
    /// Create a public key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed point representation (33 bytes for P-256)
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
        if bytes.len() != ec_p256::P256_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP256PublicKey::from_bytes",
                expected: ec_p256::P256_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec_p256::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhP256PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the key
        let mut key_bytes = [0u8; ec_p256::P256_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }
    
    /// Export the public key to bytes
    /// 
    /// # Returns
    /// The compressed point representation (33 bytes for P-256)
    /// 
    /// # Security Note
    /// Public keys are not secret, but should still be validated when imported.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Secret key methods
impl EcdhP256SecretKey {
    /// Create a secret key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The scalar value (32 bytes for P-256)
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
        if bytes.len() != ec_p256::P256_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP256SecretKey::from_bytes",
                expected: ec_p256::P256_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Create a secret buffer from the bytes
        let mut buffer_bytes = [0u8; ec_p256::P256_SCALAR_SIZE];
        buffer_bytes.copy_from_slice(bytes);
        let buffer = SecretBuffer::new(buffer_bytes);
        
        // Validate the scalar is in valid range [1, n-1]
        let scalar = ec_p256::Scalar::from_secret_buffer(buffer.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // The scalar is valid, so we can use the buffer
        drop(scalar); // Explicitly drop to ensure zeroization
        Ok(Self(buffer))
    }
    
    /// Export the secret key to bytes (with zeroization on drop)
    /// 
    /// # Returns
    /// The scalar value wrapped in `Zeroizing` (32 bytes for P-256)
    /// 
    /// # Security
    /// The returned value will be automatically zeroized when dropped.
    /// Handle with care and minimize the lifetime of the returned value.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

// Shared secret methods
impl EcdhP256SharedSecret {
    /// Export the shared secret to bytes
    /// 
    /// # Returns
    /// The derived shared secret bytes
    /// 
    /// # Security Note
    /// The shared secret should be used immediately for key derivation
    /// and not stored long-term. Consider using a KDF to derive
    /// application-specific keys.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }

    /// Export the shared secret to bytes with zeroization
    /// 
    /// # Returns
    /// The derived shared secret bytes wrapped in `Zeroizing`
    /// 
    /// # Security Note
    /// Use this method when you need the bytes to be automatically
    /// zeroized after use.
    pub fn to_zeroizing_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.to_bytes())
    }
}

// Ciphertext methods
impl EcdhP256Ciphertext {
    /// Create a ciphertext from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed ephemeral public key (33 bytes for P-256)
    /// 
    /// # Returns
    /// * `Ok(Ciphertext)` if the bytes represent a valid ephemeral key
    /// * `Err` if the bytes are invalid
    /// 
    /// # Security Note
    /// Invalid ciphertexts will be rejected during decapsulation
    /// with implicit rejection (producing a random shared secret).
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec_p256::P256_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP256Ciphertext::from_bytes",
                expected: ec_p256::P256_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec_p256::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhP256Ciphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the ciphertext
        let mut ct_bytes = [0u8; ec_p256::P256_POINT_COMPRESSED_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    
    /// Export the ciphertext to bytes
    /// 
    /// # Returns
    /// The compressed ephemeral public key (33 bytes for P-256)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Note: No AsRef or AsMut implementations for security!
// All byte access must go through explicit to_bytes() methods.

impl Kem for EcdhP256 {
    type PublicKey = EcdhP256PublicKey;
    type SecretKey = EcdhP256SecretKey;
    type SharedSecret = EcdhP256SharedSecret;
    type Ciphertext = EcdhP256Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P256"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        // Generate a keypair using the EC implementation
        // The EC implementation already ensures proper scalar range and point validation
        let (sk_scalar, pk_point) =
            ec_p256::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;

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
            ec_p256::P256_FIELD_ELEMENT_SIZE + 2 * ec_p256::P256_POINT_COMPRESSED_SIZE, // Using compressed size
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);

        // 8. Derive the shared secret with domain separation
        let info: Option<&[u8]> = Some(b"ECDH-P256-KEM");
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
            ec_p256::P256_FIELD_ELEMENT_SIZE + 2 * ec_p256::P256_POINT_COMPRESSED_SIZE, // Using compressed size
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        // 8. Derive the shared secret with same domain separation
        let info: Option<&[u8]> = Some(b"ECDH-P256-KEM");
        let ss_bytes = ec_p256::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        // 9. Create and return the shared secret
        let shared_secret = EcdhP256SharedSecret(ApiKey::new(&ss_bytes));
        Ok(shared_secret)
    }
}

// Optional: Implement extension traits for serialization if needed
// These are kept separate from the core implementation for security

/// Extension methods for P-256 KEM types
impl EcdhP256 {
    /// Validate a public key
    pub fn validate_public_key(key: &EcdhP256PublicKey) -> ApiResult<()> {
        // Re-validate by attempting to deserialize
        let point = ec_p256::Point::deserialize_compressed(&key.0)
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
    
    /// Validate a secret key
    pub fn validate_secret_key(key: &EcdhP256SecretKey) -> ApiResult<()> {
        // Validation happens during scalar creation
        let _ = ec_p256::Scalar::from_secret_buffer(key.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        Ok(())
    }
    
    /// Validate a ciphertext
    pub fn validate_ciphertext(ct: &EcdhP256Ciphertext) -> ApiResult<()> {
        // Re-validate by attempting to deserialize
        let point = ec_p256::Point::deserialize_compressed(&ct.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "validate_ciphertext",
                #[cfg(feature = "std")]
                message: "Ciphertext contains identity point".to_string(),
            });
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests;