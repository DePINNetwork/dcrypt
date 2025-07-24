// crates/kem/src/kyber/kem.rs

//! Core Kyber KEM logic using the `api::Kem` trait.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use dcrypt_api::{Kem as KemTrait, Result as ApiResult, error::Error as ApiError, Key as ApiKey};
use dcrypt_algorithms::error::Error as AlgoError;
use crate::error::Error as KemError; // KEM-specific errors
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{CryptoRng, RngCore};
use core::marker::PhantomData;

use super::params::KyberParams;
use super::ind_cca::{kem_keygen, kem_encaps, kem_decaps}; // IND-CCA2 scheme components

/// Kyber Public Key (byte representation).
#[derive(Clone, Debug, Zeroize)]
pub struct KyberPublicKey(Vec<u8>);
impl KyberPublicKey {
    /// Creates a new public key from byte vector.
    pub fn new(data: Vec<u8>) -> Self { Self(data) }
    /// Consumes the key and returns the inner byte vector.
    pub fn into_vec(self) -> Vec<u8> { self.0 }
}
impl AsRef<[u8]> for KyberPublicKey { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for KyberPublicKey { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }

/// Kyber Secret Key (byte representation).
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey(Vec<u8>);
impl KyberSecretKey {
    /// Creates a new secret key from byte vector.
    pub fn new(data: Vec<u8>) -> Self { Self(data) }
    /// Clones the inner byte vector and returns it.
    pub fn to_vec(&self) -> Vec<u8> { self.0.clone() }
}
impl AsRef<[u8]> for KyberSecretKey { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for KyberSecretKey { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }

/// Kyber Ciphertext (byte representation).
#[derive(Clone, Debug)] 
pub struct KyberCiphertext(Vec<u8>);
impl KyberCiphertext {
    /// Creates a new ciphertext from byte vector.
    pub fn new(data: Vec<u8>) -> Self { Self(data) }
    /// Consumes the ciphertext and returns the inner byte vector.
    pub fn into_vec(self) -> Vec<u8> { self.0 }
}
impl AsRef<[u8]> for KyberCiphertext { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for KyberCiphertext { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }

/// Kyber Shared Secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KyberSharedSecret(ApiKey); 
impl KyberSharedSecret {
    /// Creates a new shared secret from an ApiKey.
    pub fn new(key: ApiKey) -> Self { Self(key) }
    /// Clones the inner ApiKey and returns it.
    pub fn to_key(&self) -> ApiKey { self.0.clone() }
}

impl core::fmt::Debug for KyberSharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KyberSharedSecret")
            .field("length", &self.0.as_ref().len())
            .finish()
    }
}

impl AsRef<[u8]> for KyberSharedSecret { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl AsMut<[u8]> for KyberSharedSecret { fn as_mut(&mut self) -> &mut [u8] { self.0.as_mut() } }

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

    fn keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> ApiResult<Self::KeyPair> {
        let (pk_bytes, sk_bytes) = kem_keygen::<P, R>(rng)
            .map_err(|algo_err| ApiError::from(KemError::from(algo_err)))?;
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
        if public_key.as_ref().len() != P::PUBLIC_KEY_BYTES {
            return Err(ApiError::InvalidKey { 
                context: "Kyber public key", 
                #[cfg(feature = "std")] 
                message: format!("Incorrect length: expected {}, got {}", P::PUBLIC_KEY_BYTES, public_key.as_ref().len())
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
        if secret_key.as_ref().len() != P::SECRET_KEY_BYTES {
            return Err(ApiError::InvalidKey { 
                context: "Kyber secret key", 
                #[cfg(feature = "std")] 
                message: format!("Incorrect length: expected {}, got {}", P::SECRET_KEY_BYTES, secret_key.as_ref().len())
            });
        }
        if ciphertext.as_ref().len() != P::CIPHERTEXT_BYTES {
            return Err(ApiError::InvalidCiphertext { 
                context: "Kyber ciphertext", 
                #[cfg(feature = "std")] 
                message: format!("Incorrect length: expected {}, got {}", P::CIPHERTEXT_BYTES, ciphertext.as_ref().len())
            });
        }

        // kem_decaps expects &Vec<u8>, so we need to pass references to the inner Vecs
        let ss_bytes_fixed = kem_decaps::<P>(&secret_key.0, &ciphertext.0)
            .map_err(|algo_err| {
                match algo_err {
                    AlgoError::Processing { .. } => {
                        ApiError::DecryptionFailed { 
                            context: P::NAME, 
                            #[cfg(feature = "std")] 
                            message: "Decapsulation failed".into() 
                        }
                    }
                    _ => ApiError::from(KemError::from(algo_err))
                }
            })?;
            
        Ok(KyberSharedSecret::new(ApiKey::new(ss_bytes_fixed.as_ref())))
    }
}