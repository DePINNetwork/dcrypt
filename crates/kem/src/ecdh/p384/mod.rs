// File: crates/kem/src/ecdh/p384.rs
//! ECDH-KEM with NIST P-384
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-384 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::p384 as ec_p384;
use dcrypt_api::{error::Error as ApiError, Kem, Key as ApiKey, Result as ApiResult};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

// Public key methods
impl EcdhP384PublicKey {
    /// Create a public key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed point representation (49 bytes for P-384)
    /// 
    /// # Returns
    /// * `Ok(PublicKey)` if the bytes represent a valid point on the curve
    /// * `Err` if the bytes are invalid (wrong length, invalid point, or identity)
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec_p384::P384_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP384PublicKey::from_bytes",
                expected: ec_p384::P384_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec_p384::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhP384PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the key
        let mut key_bytes = [0u8; ec_p384::P384_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }
    
    /// Export the public key to bytes
    /// 
    /// # Returns
    /// The compressed point representation (49 bytes for P-384)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Secret key methods
impl EcdhP384SecretKey {
    /// Create a secret key from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The scalar value (48 bytes for P-384)
    /// 
    /// # Returns
    /// * `Ok(SecretKey)` if the bytes represent a valid scalar
    /// * `Err` if the bytes are invalid (wrong length or out of range)
    /// 
    /// # Security
    /// The input bytes should be treated as sensitive material and zeroized after use
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec_p384::P384_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP384SecretKey::from_bytes",
                expected: ec_p384::P384_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Create a secret buffer from the bytes
        let mut buffer_bytes = [0u8; ec_p384::P384_SCALAR_SIZE];
        buffer_bytes.copy_from_slice(bytes);
        let buffer = SecretBuffer::new(buffer_bytes);
        
        // Validate the scalar is in valid range [1, n-1]
        let scalar = ec_p384::Scalar::from_secret_buffer(buffer.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // The scalar is valid, so we can use the buffer
        drop(scalar); // Explicitly drop to ensure zeroization
        Ok(Self(buffer))
    }
    
    /// Export the secret key to bytes (with zeroization on drop)
    /// 
    /// # Returns
    /// The scalar value wrapped in `Zeroizing` (48 bytes for P-384)
    /// 
    /// # Security
    /// The returned value will be automatically zeroized when dropped
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

// Shared secret methods
impl EcdhP384SharedSecret {
    /// Export the shared secret to bytes
    /// 
    /// # Returns
    /// The derived shared secret bytes (48 bytes for P-384 with SHA-384)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}

// Ciphertext methods
impl EcdhP384Ciphertext {
    /// Create a ciphertext from bytes with validation
    /// 
    /// # Arguments
    /// * `bytes` - The compressed ephemeral public key (49 bytes for P-384)
    /// 
    /// # Returns
    /// * `Ok(Ciphertext)` if the bytes represent a valid ephemeral key
    /// * `Err` if the bytes are invalid
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        // Validate length
        if bytes.len() != ec_p384::P384_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP384Ciphertext::from_bytes",
                expected: ec_p384::P384_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        
        // Validate it's a valid point on the curve
        let point = ec_p384::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        
        // Reject the identity point
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhP384Ciphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        
        // Create the ciphertext
        let mut ct_bytes = [0u8; ec_p384::P384_POINT_COMPRESSED_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    
    /// Export the ciphertext to bytes
    /// 
    /// # Returns
    /// The compressed ephemeral public key (49 bytes for P-384)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// AsRef/AsMut implementations
impl AsRef<[u8]> for EcdhP384PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdhP384PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl AsRef<[u8]> for EcdhP384SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for EcdhP384SecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl AsRef<[u8]> for EcdhP384SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for EcdhP384SharedSecret {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl AsRef<[u8]> for EcdhP384Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdhP384Ciphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Kem for EcdhP384 {
    type PublicKey = EcdhP384PublicKey;
    type SecretKey = EcdhP384SecretKey;
    type SharedSecret = EcdhP384SharedSecret;
    type Ciphertext = EcdhP384Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P384"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        // Generate a keypair using the EC implementation
        // The EC implementation already ensures proper scalar range and point validation
        let (sk_scalar, pk_point) =
            ec_p384::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;

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
        let (ephemeral_scalar, ephemeral_point) =
            ec_p384::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;

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
            ec_p384::P384_FIELD_ELEMENT_SIZE + 2 * ec_p384::P384_POINT_COMPRESSED_SIZE, // Using compressed size
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);

        // 8. Derive the shared secret with domain separation
        let info: Option<&[u8]> = Some(b"ECDH-P384-KEM");
        let ss_bytes = ec_p384::kdf_hkdf_sha384_for_ecdh_kem(&kdf_ikm, info)
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
            ec_p384::P384_FIELD_ELEMENT_SIZE + 2 * ec_p384::P384_POINT_COMPRESSED_SIZE, // Using compressed size
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        // 8. Derive the shared secret with same domain separation
        let info: Option<&[u8]> = Some(b"ECDH-P384-KEM");
        let ss_bytes = ec_p384::kdf_hkdf_sha384_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        // 9. Create and return the shared secret
        let shared_secret = EcdhP384SharedSecret(ApiKey::new(&ss_bytes));
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests;