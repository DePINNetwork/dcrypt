// File: crates/kem/src/ecdh/p192.rs
//! ECDH-KEM with NIST P-192
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-192 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//! This implementation uses compressed point format.

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::p192 as ec;
use dcrypt_api::{error::Error as ApiError, Kem, Key as ApiKey, Result as ApiResult};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ECDH KEM with P-192 curve
pub struct EcdhP192;

/// Public key for ECDH-P192 KEM (compressed EC point)
#[derive(Clone, Zeroize)]
pub struct EcdhP192PublicKey([u8; ec::P192_POINT_COMPRESSED_SIZE]);

/// Secret key for ECDH-P192 KEM (scalar value)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP192SecretKey(SecretBuffer<{ ec::P192_SCALAR_SIZE }>);

/// Shared secret from ECDH-P192 KEM
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP192SharedSecret(ApiKey);

/// Ciphertext for ECDH-P192 KEM (compressed ephemeral public key)
#[derive(Clone)]
pub struct EcdhP192Ciphertext([u8; ec::P192_POINT_COMPRESSED_SIZE]);

// AsRef/AsMut implementations
impl AsRef<[u8]> for EcdhP192PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdhP192PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl AsRef<[u8]> for EcdhP192SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for EcdhP192SecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl AsRef<[u8]> for EcdhP192SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for EcdhP192SharedSecret {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl AsRef<[u8]> for EcdhP192Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdhP192Ciphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

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