//! ECIES implementation for NIST P-256.
use dcrypt_algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt_algorithms::ec::p256 as ec;
use dcrypt_algorithms::types::Nonce;
use dcrypt_api::error::Error as ApiError;
use dcrypt_api::traits::symmetric::{DecryptOperation, EncryptOperation}; // Import operation traits
use dcrypt_api::traits::Pke;
use dcrypt_api::traits::SymmetricCipher as ApiSymmetricCipherTrait;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::format;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

use super::{
    derive_symmetric_key_hkdf_sha256, EciesCiphertextComponents, CHACHA20POLY1305_KEY_LEN,
    CHACHA20POLY1305_NONCE_LEN,
};
use crate::error::Error as PkeError;

/// Public key for ECIES P-256. Stores serialized uncompressed point.
#[derive(Clone, Debug)]
pub struct EciesP256PublicKey([u8; ec::P256_POINT_UNCOMPRESSED_SIZE]);

impl AsRef<[u8]> for EciesP256PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Secret key for ECIES P-256. Stores serialized scalar.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EciesP256SecretKey([u8; ec::P256_SCALAR_SIZE]);

impl AsRef<[u8]> for EciesP256SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct EciesP256;

impl Pke for EciesP256 {
    type PublicKey = EciesP256PublicKey;
    type SecretKey = EciesP256SecretKey;
    type Ciphertext = Vec<u8>;

    fn name() -> &'static str {
        "ECIES-P256-HKDF-SHA256-ChaCha20Poly1305"
    }

    fn keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> dcrypt_api::error::Result<(Self::PublicKey, Self::SecretKey)> {
        let (sk_scalar, pk_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(PkeError::from(e)))?;
        Ok((
            EciesP256PublicKey(pk_point.serialize_uncompressed()),
            EciesP256SecretKey(sk_scalar.serialize()),
        ))
    }

    fn encrypt<R: RngCore + CryptoRng>(
        pk_recipient: &Self::PublicKey,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        rng: &mut R,
    ) -> dcrypt_api::error::Result<Self::Ciphertext> {
        let pk_recipient_point = ec::Point::deserialize_uncompressed(&pk_recipient.0)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;
        if pk_recipient_point.is_identity() {
            return Err(ApiError::from(PkeError::EncryptionFailed(
                "Recipient PK is point at infinity",
            )));
        }

        let (ephemeral_sk_scalar, ephemeral_pk_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(PkeError::from(e)))?;
        let r_bytes_uncompressed = ephemeral_pk_point.serialize_uncompressed();

        let shared_point = ec::scalar_mult(&ephemeral_sk_scalar, &pk_recipient_point)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::from(PkeError::EncryptionFailed(
                "ECDH resulted in point at infinity",
            )));
        }
        let mut z_bytes = shared_point.x_coordinate_bytes();

        let info_str = format!("{}-KeyMaterial", Self::name());
        let mut derived_key_material = derive_symmetric_key_hkdf_sha256(
            &z_bytes,
            &r_bytes_uncompressed,
            CHACHA20POLY1305_KEY_LEN,
            Some(info_str.as_bytes()),
        )
        .map_err(ApiError::from)?;

        let mut encryption_key_arr = [0u8; CHACHA20POLY1305_KEY_LEN];
        encryption_key_arr.copy_from_slice(&derived_key_material);

        drop(ephemeral_sk_scalar);
        z_bytes.zeroize();
        derived_key_material.zeroize();

        let aead_cipher_impl = ChaCha20Poly1305::new(&encryption_key_arr);
        let aead_nonce = Nonce::<CHACHA20POLY1305_NONCE_LEN>::random(rng);

        let aead_ciphertext_api_obj =
            <ChaCha20Poly1305 as ApiSymmetricCipherTrait>::encrypt(&aead_cipher_impl)
                .with_nonce(&aead_nonce)
                .with_aad(aad.unwrap_or(&[]))
                .encrypt(plaintext)?;

        let ecies_components = EciesCiphertextComponents {
            ephemeral_public_key: r_bytes_uncompressed.to_vec(),
            aead_nonce: aead_nonce.as_ref().to_vec(),
            aead_ciphertext_tag: aead_ciphertext_api_obj.as_ref().to_vec(),
        };

        Ok(ecies_components.serialize())
    }

    fn decrypt(
        sk_recipient: &Self::SecretKey,
        ciphertext_bytes: &Self::Ciphertext,
        aad: Option<&[u8]>,
    ) -> dcrypt_api::error::Result<Vec<u8>> {
        let ecies_components =
            EciesCiphertextComponents::deserialize(ciphertext_bytes).map_err(ApiError::from)?;

        let r_point = ec::Point::deserialize_uncompressed(&ecies_components.ephemeral_public_key)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;
        if r_point.is_identity() {
            return Err(ApiError::from(PkeError::DecryptionFailed(
                "Ephemeral PK is point at infinity",
            )));
        }

        let sk_recipient_scalar = ec::Scalar::deserialize(&sk_recipient.0)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;

        let shared_point = ec::scalar_mult(&sk_recipient_scalar, &r_point)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::from(PkeError::DecryptionFailed(
                "ECDH resulted in point at infinity",
            )));
        }
        let mut z_bytes = shared_point.x_coordinate_bytes();

        let info_str = format!("{}-KeyMaterial", Self::name());
        let mut derived_key_material = derive_symmetric_key_hkdf_sha256(
            &z_bytes,
            &ecies_components.ephemeral_public_key,
            CHACHA20POLY1305_KEY_LEN,
            Some(info_str.as_bytes()),
        )
        .map_err(ApiError::from)?;

        let mut encryption_key_arr = [0u8; CHACHA20POLY1305_KEY_LEN];
        encryption_key_arr.copy_from_slice(&derived_key_material);

        z_bytes.zeroize();
        derived_key_material.zeroize();

        let aead_nonce =
            Nonce::<CHACHA20POLY1305_NONCE_LEN>::from_slice(&ecies_components.aead_nonce)
                .map_err(|e| ApiError::from(PkeError::from(e)))?;

        let aead_cipher_impl = ChaCha20Poly1305::new(&encryption_key_arr);

        let aead_ct_api_obj = dcrypt_api::Ciphertext::new(&ecies_components.aead_ciphertext_tag);

        let plaintext = <ChaCha20Poly1305 as ApiSymmetricCipherTrait>::decrypt(&aead_cipher_impl)
            .with_nonce(&aead_nonce)
            .with_aad(aad.unwrap_or(&[]))
            .decrypt(&aead_ct_api_obj)
            .map_err(|_| {
                // Collapse any AEAD-layer failure (bad key / AAD / tag / tampering)
                // into a single high-level ECIES decryption failure.
                ApiError::from(PkeError::DecryptionFailed("AEAD authentication failed"))
            })?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests;
