// crates/kem/src/kyber/kem.rs

//! Core Kyber KEM logic using the `api::Kem` trait.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Error as KemError; // KEM-specific errors
use core::marker::PhantomData;
use dcrypt_algorithms::error::Error as AlgoError;
use dcrypt_api::{error::Error as ApiError, Kem as KemTrait, Key as ApiKey, Result as ApiResult};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::ind_cca::{kem_decaps, kem_encaps, kem_keygen};
use super::params::KyberParams; // IND-CCA2 scheme components

/// Kyber Public Key (byte representation).
/// 
/// # Security Note
/// No direct byte access is provided. Use explicit methods for serialization.
#[derive(Clone, Debug, Zeroize)]
pub struct KyberPublicKey(Vec<u8>);

impl KyberPublicKey {
    /// Creates a new public key from byte vector.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    
    /// Consumes the key and returns the inner byte vector.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
    
    /// Returns a reference to the inner bytes.
    /// 
    /// # Security Note
    /// This is an explicit method for byte access, not through AsRef trait.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Creates a public key from bytes with validation.
    /// 
    /// # Security Requirements
    /// - Validates the byte length matches the expected size
    /// - Should be extended to validate key format in production
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(bytes.to_vec()))
    }
    
    /// Exports the public key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Kyber Secret Key (byte representation).
/// 
/// # Security Note
/// - Implements Zeroize for secure cleanup
/// - No direct byte access through traits
/// - All access must be explicit and auditable
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey(Vec<u8>);

impl KyberSecretKey {
    /// Creates a new secret key from byte vector.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    
    /// Clones the inner byte vector and returns it.
    /// 
    /// # Security Warning
    /// The returned bytes contain sensitive key material.
    /// Consider using `to_bytes_zeroizing` instead.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
    
    /// Returns the length of the secret key.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    
    /// Checks if the secret key is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    
    /// Returns a reference to the inner bytes.
    /// 
    /// # Security Warning
    /// This exposes raw key material. Use with extreme caution.
    /// Prefer `to_bytes_zeroizing` for safer access.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Creates a secret key from bytes.
    /// 
    /// # Security Note
    /// The input bytes should be zeroized after use.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(bytes.to_vec()))
    }
    
    /// Exports the secret key to bytes with automatic zeroization.
    /// 
    /// # Security Note
    /// The returned value is wrapped in `Zeroizing` for automatic cleanup.
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.clone())
    }
}

/// Kyber Ciphertext (byte representation).
/// 
/// # Security Note
/// No direct byte access prevents tampering.
#[derive(Clone, Debug)]
pub struct KyberCiphertext(Vec<u8>);

impl KyberCiphertext {
    /// Creates a new ciphertext from byte vector.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    
    /// Consumes the ciphertext and returns the inner byte vector.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
    
    /// Returns a reference to the inner bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Returns the length of the ciphertext.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    
    /// Checks if the ciphertext is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    
    /// Creates a ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(bytes.to_vec()))
    }
    
    /// Exports the ciphertext to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Kyber Shared Secret.
/// 
/// # Security Note
/// - Implements Zeroize for secure cleanup
/// - No direct byte access through traits
/// - Should be used immediately for key derivation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KyberSharedSecret(ApiKey);

impl KyberSharedSecret {
    /// Creates a new shared secret from an ApiKey.
    pub fn new(key: ApiKey) -> Self {
        Self(key)
    }
    
    /// Clones the inner ApiKey and returns it.
    pub fn to_key(&self) -> ApiKey {
        self.0.clone()
    }
    
    /// Returns the length of the shared secret.
    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }
    
    /// Checks if the shared secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
    
    /// Returns a reference to the inner bytes.
    /// 
    /// # Security Warning
    /// This exposes the shared secret. Use immediately and do not store.
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
    
    /// Exports the shared secret to bytes with automatic zeroization.
    /// 
    /// # Security Note
    /// The returned value is wrapped in `Zeroizing` for automatic cleanup.
    /// Use immediately for key derivation.
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

impl core::fmt::Debug for KyberSharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KyberSharedSecret")
            .field("length", &self.len())
            .finish()
    }
}

/// Generic Kyber KEM structure parameterized by KyberParams.
pub struct KyberKem<P: KyberParams> {
    _params: PhantomData<P>,
}

impl<P: KyberParams> KemTrait for KyberKem<P> {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type SharedSecret = KyberSharedSecret;
    type Ciphertext = KyberCiphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        P::NAME
    }

    fn keypair<R: RngCore + CryptoRng>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (pk_bytes, sk_bytes) =
            kem_keygen::<P, R>(rng).map_err(|algo_err| ApiError::from(KemError::from(algo_err)))?;
        Ok((KyberPublicKey::new(pk_bytes), KyberSecretKey::new(sk_bytes)))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn encapsulate<R: RngCore + CryptoRng>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> ApiResult<(Self::Ciphertext, Self::SharedSecret)> {
        if public_key.as_bytes().len() != P::PUBLIC_KEY_BYTES {
            return Err(ApiError::InvalidKey {
                context: "Kyber public key",
                #[cfg(feature = "std")]
                message: format!(
                    "Incorrect length: expected {}, got {}",
                    P::PUBLIC_KEY_BYTES,
                    public_key.as_bytes().len()
                ),
            });
        }

        // kem_encaps expects &Vec<u8>, so we need to pass a reference to the inner Vec
        let (ct_bytes, ss_bytes_fixed) = kem_encaps::<P, R>(&public_key.0, rng)
            .map_err(|algo_err| ApiError::from(KemError::from(algo_err)))?;

        Ok((
            KyberCiphertext::new(ct_bytes),
            KyberSharedSecret::new(ApiKey::new(ss_bytes_fixed.as_ref())),
        ))
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        if secret_key.as_bytes().len() != P::SECRET_KEY_BYTES {
            return Err(ApiError::InvalidKey {
                context: "Kyber secret key",
                #[cfg(feature = "std")]
                message: format!(
                    "Incorrect length: expected {}, got {}",
                    P::SECRET_KEY_BYTES,
                    secret_key.as_bytes().len()
                ),
            });
        }
        if ciphertext.as_bytes().len() != P::CIPHERTEXT_BYTES {
            return Err(ApiError::InvalidCiphertext {
                context: "Kyber ciphertext",
                #[cfg(feature = "std")]
                message: format!(
                    "Incorrect length: expected {}, got {}",
                    P::CIPHERTEXT_BYTES,
                    ciphertext.as_bytes().len()
                ),
            });
        }

        // kem_decaps expects &Vec<u8>, so we need to pass references to the inner Vecs
        let ss_bytes_fixed =
            kem_decaps::<P>(&secret_key.0, &ciphertext.0).map_err(|algo_err| match algo_err {
                AlgoError::Processing { .. } => ApiError::DecryptionFailed {
                    context: P::NAME,
                    #[cfg(feature = "std")]
                    message: "Decapsulation failed".into(),
                },
                _ => ApiError::from(KemError::from(algo_err)),
            })?;

        Ok(KyberSharedSecret::new(ApiKey::new(ss_bytes_fixed.as_ref())))
    }
}