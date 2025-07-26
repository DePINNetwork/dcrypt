// File: crates/kem/src/ecdh/b283k.rs
//! ECDH-KEM with sect283k1 (B-283k)
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the SECG binary curve sect283k1.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::b283k as ec_b283k;
use dcrypt_api::{error::Error as ApiError, Kem, Key as ApiKey, Result as ApiResult};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

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

// AsRef/AsMut implementations
impl AsRef<[u8]> for EcdhB283kPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdhB283kPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl AsRef<[u8]> for EcdhB283kSecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for EcdhB283kSecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl AsRef<[u8]> for EcdhB283kSharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for EcdhB283kSharedSecret {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl AsRef<[u8]> for EcdhB283kCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdhB283kCiphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

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