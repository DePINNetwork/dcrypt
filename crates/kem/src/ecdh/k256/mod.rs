// File: crates/kem/src/ecdh/k256/mod.rs
//! ECDH-KEM with secp256k1 (K-256)
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the secp256k1 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.
//! 
//! # Security Features
//! 
//! - No direct byte access to keys or secrets (prevents tampering)
//! - Constant-time operations where applicable
//! - Proper validation of curve points
//! - Secure key derivation using HKDF-SHA256

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::k256 as ec_k256;
use dcrypt_api::{error::Error as ApiError, Kem, Key as ApiKey, Result as ApiResult};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

// Public key methods
impl EcdhK256PublicKey {
    /// Create a public key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed point representation (33 bytes for K-256)
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
        if bytes.len() != ec_k256::K256_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhK256PublicKey::from_bytes",
                expected: ec_k256::K256_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec_k256::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhK256PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the key
        let mut key_bytes = [0u8; ec_k256::K256_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }
    
    /// Export the public key to bytes
    /// 
    /// # Returns
    /// The compressed point representation (33 bytes for K-256)
    /// 
    /// # Security Note
    /// Public keys are not secret, but care should be taken to verify
    /// authenticity when receiving public keys from untrusted sources.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Secret key methods
impl EcdhK256SecretKey {
    /// Create a secret key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The scalar value (32 bytes for K-256)
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
        if bytes.len() != ec_k256::K256_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhK256SecretKey::from_bytes",
                expected: ec_k256::K256_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Create a secret buffer from the bytes
        let mut buffer_bytes = [0u8; ec_k256::K256_SCALAR_SIZE];
        buffer_bytes.copy_from_slice(bytes);
        let buffer = SecretBuffer::new(buffer_bytes);
        
        // Validate the scalar is in valid range [1, n-1]
        let scalar = ec_k256::Scalar::from_secret_buffer(buffer.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // The scalar is valid, so we can use the buffer
        drop(scalar); // Explicitly drop to ensure zeroization
        Ok(Self(buffer))
    }
    
    /// Export the secret key to bytes (with zeroization on drop)
    /// 
    /// # Returns
    /// The scalar value wrapped in `Zeroizing` (32 bytes for K-256)
    /// 
    /// # Security
    /// The returned value will be automatically zeroized when dropped.
    /// Handle with extreme care and minimize the lifetime of the returned value.
    /// 
    /// # Example
    /// ```no_run
    /// # use dcrypt_kem::ecdh::EcdhK256SecretKey;
    /// # use zeroize::Zeroizing;
    /// # fn example(key: &EcdhK256SecretKey) {
    /// let secret_bytes = key.to_bytes();
    /// // Use secret_bytes immediately...
    /// // Automatically zeroized when secret_bytes goes out of scope
    /// # }
    /// ```
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

// Shared secret methods
impl EcdhK256SharedSecret {
    /// Export the shared secret to bytes
    /// 
    /// # Returns
    /// The derived shared secret bytes (32 bytes for K-256 with SHA-256)
    /// 
    /// # Security Note
    /// The shared secret should be used immediately for key derivation
    /// and not stored long-term. Consider using a KDF to derive
    /// application-specific keys.
    /// 
    /// # Example
    /// ```no_run
    /// # use dcrypt_kem::ecdh::EcdhK256SharedSecret;
    /// # fn example(shared_secret: &EcdhK256SharedSecret) {
    /// let ss_bytes = shared_secret.to_bytes();
    /// // Immediately derive application keys:
    /// // let app_key = kdf(&ss_bytes, b"MyApp v1.0", 32);
    /// # }
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
    
    /// Export the shared secret to bytes with zeroization
    /// 
    /// # Returns
    /// The shared secret wrapped in `Zeroizing` for automatic cleanup
    /// 
    /// # Security Note
    /// Use this method when you need to ensure the shared secret
    /// is zeroized after use.
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

// Ciphertext methods
impl EcdhK256Ciphertext {
    /// Create a ciphertext from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed ephemeral public key (33 bytes for K-256)
    /// 
    /// # Returns
    /// * `Ok(Ciphertext)` if the bytes represent a valid ephemeral key
    /// * `Err` if the bytes are invalid
    /// 
    /// # Security Note
    /// This validates the ephemeral public key to ensure it's a valid
    /// point on the curve, preventing invalid ciphertext attacks.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec_k256::K256_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhK256Ciphertext::from_bytes",
                expected: ec_k256::K256_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec_k256::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhK256Ciphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the ciphertext
        let mut ct_bytes = [0u8; ec_k256::K256_POINT_COMPRESSED_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    
    /// Export the ciphertext to bytes
    /// 
    /// # Returns
    /// The compressed ephemeral public key (33 bytes for K-256)
    /// 
    /// # Security Note
    /// Ciphertexts are public data and can be safely transmitted
    /// over insecure channels.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// NO AsRef or AsMut implementations - this prevents direct byte access
// and forces use of explicit to_bytes() methods with proper documentation

impl Kem for EcdhK256 {
    type PublicKey = EcdhK256PublicKey;
    type SecretKey = EcdhK256SecretKey;
    type SharedSecret = EcdhK256SharedSecret;
    type Ciphertext = EcdhK256Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-K256"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) =
            ec_k256::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;

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
        let (ephemeral_scalar, ephemeral_point) =
            ec_k256::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;

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
            ec_k256::K256_FIELD_ELEMENT_SIZE + 2 * ec_k256::K256_POINT_COMPRESSED_SIZE,
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);

        // 8. Derive the shared secret with domain separation
        let info: Option<&[u8]> = Some(b"ECDH-K256-KEM");
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
            ec_k256::K256_FIELD_ELEMENT_SIZE + 2 * ec_k256::K256_POINT_COMPRESSED_SIZE,
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        // 8. Derive the shared secret with same domain separation
        let info: Option<&[u8]> = Some(b"ECDH-K256-KEM");
        let ss_bytes = ec_k256::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        // 9. Create and return the shared secret
        let shared_secret = EcdhK256SharedSecret(ApiKey::new(&ss_bytes));
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests;