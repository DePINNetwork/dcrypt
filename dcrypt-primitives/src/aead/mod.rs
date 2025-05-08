//! Authenticated Encryption with Associated Data (AEAD) with builder pattern
//!
//! This module provides implementations of authenticated encryption algorithms
//! with an ergonomic builder pattern for operations.
//!
//! ## Example usage
//!
//! ```
//! use dcrypt_primitives::aead::{ChaCha20Poly1305Cipher, AeadCipher, AeadEncryptionBuilder, AeadDecryptionBuilder};
//! use rand::rngs::OsRng;
//! 
//! // Generate key and nonce
//! let key = ChaCha20Poly1305Cipher::generate_key(&mut OsRng).unwrap();
//! let nonce = ChaCha20Poly1305Cipher::generate_nonce(&mut OsRng).unwrap();
//! 
//! // Create cipher instance
//! let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
//! 
//! // Encrypt with builder pattern
//! let ciphertext = cipher.encrypt()
//!     .with_nonce(&nonce)
//!     .with_aad(b"additional data")
//!     .encrypt(b"secret message").unwrap();
//! 
//! // Decrypt with builder pattern
//! let plaintext = cipher.decrypt()
//!     .with_nonce(&nonce)
//!     .with_aad(b"additional data")
//!     .decrypt(&ciphertext).unwrap();
//! 
//! assert_eq!(plaintext, b"secret message");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Core modules
#[cfg(feature = "alloc")]
pub mod gcm;

#[cfg(feature = "alloc")]
pub mod chacha20poly1305;

#[cfg(feature = "alloc")]
pub mod xchacha20poly1305;

// Re-export for convenience when alloc is available
#[cfg(feature = "alloc")]
pub use self::gcm::Gcm;

#[cfg(feature = "alloc")]
pub use self::chacha20poly1305::ChaCha20Poly1305;

#[cfg(feature = "alloc")]
pub use self::xchacha20poly1305::XChaCha20Poly1305;

use crate::error::{Error, Result};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use zeroize::Zeroize;
use core::marker::PhantomData;
use rand::{CryptoRng, RngCore};
use crate::types::{SecretBytes, Tag};
use crate::{Nonce12, Nonce16, Nonce24};

/// Marker trait for AEAD algorithms
pub trait AeadAlgorithm {
    /// Key size in bytes
    const KEY_SIZE: usize;
    
    /// Tag size in bytes
    const TAG_SIZE: usize;
    
    /// Algorithm name
    fn name() -> &'static str;
}

/// Type-level constants for ChaCha20-Poly1305
pub enum ChaCha20Poly1305Algorithm {}

impl AeadAlgorithm for ChaCha20Poly1305Algorithm {
    const KEY_SIZE: usize = 32;
    const TAG_SIZE: usize = 16;
    
    fn name() -> &'static str {
        "ChaCha20-Poly1305"
    }
}

/// Base trait for operation builders
pub trait Builder<T> {
    /// Execute the operation and produce a result
    fn build(self) -> Result<T>;
    
    /// Reset the builder to its initial state
    fn reset(&mut self);
}

/// Trait for encryption builders with AEAD algorithms
pub trait AeadEncryptionBuilder<'a, A: AeadAlgorithm>: Builder<Vec<u8>> {
    /// Set the nonce for encryption - ChaCha20Poly1305 uses Nonce12
    fn with_nonce(self, nonce: &'a Nonce12) -> Self;
    
    /// Set associated data for authenticated encryption
    fn with_aad(self, aad: &'a [u8]) -> Self;
    
    /// Set plaintext and execute encryption
    fn encrypt(self, plaintext: &'a [u8]) -> Result<Vec<u8>>;
}

/// Trait for decryption builders with AEAD algorithms
pub trait AeadDecryptionBuilder<'a, A: AeadAlgorithm>: Builder<Vec<u8>> {
    /// Set the nonce for decryption - ChaCha20Poly1305 uses Nonce12
    fn with_nonce(self, nonce: &'a Nonce12) -> Self;
    
    /// Set associated data for authenticated decryption
    fn with_aad(self, aad: &'a [u8]) -> Self;
    
    /// Set ciphertext and execute decryption
    fn decrypt(self, ciphertext: &'a [u8]) -> Result<Vec<u8>>;
}

/// Trait for AEAD ciphers with improved type safety
pub trait AeadCipher {
    /// The algorithm this cipher implements
    type Algorithm: AeadAlgorithm;
    
    /// Key type with appropriate size guarantee
    type Key: AsRef<[u8]> + AsMut<[u8]> + Clone + Zeroize;
    
    /// Creates a new AEAD cipher instance
    fn new(key: &Self::Key) -> Result<Self> where Self: Sized;
    
    /// Begin encryption operation with builder pattern
    fn encrypt<'a>(&'a self) -> impl AeadEncryptionBuilder<'a, Self::Algorithm>;
    
    /// Begin decryption operation with builder pattern
    fn decrypt<'a>(&'a self) -> impl AeadDecryptionBuilder<'a, Self::Algorithm>;
    
    /// Generate a random key
    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key>;
    
    /// Generate a random nonce for ChaCha20Poly1305
    fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Nonce12>;
    
    /// Returns the cipher name
    fn name() -> &'static str {
        Self::Algorithm::name()
    }
    
    /// Returns the key size in bytes
    fn key_size() -> usize {
        Self::Algorithm::KEY_SIZE
    }
    
    /// Returns the tag size in bytes
    fn tag_size() -> usize {
        Self::Algorithm::TAG_SIZE
    }
}

/// Implementation of ChaCha20-Poly1305 with enhanced type safety
#[cfg(feature = "alloc")]
pub struct ChaCha20Poly1305Cipher {
    inner: chacha20poly1305::ChaCha20Poly1305,
    key: SecretBytes<32>,
}

#[cfg(feature = "alloc")]
impl AeadCipher for ChaCha20Poly1305Cipher {
    type Algorithm = ChaCha20Poly1305Algorithm;
    type Key = SecretBytes<32>;
    
    fn new(key: &Self::Key) -> Result<Self> {
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key.as_ref());
        
        let inner = chacha20poly1305::ChaCha20Poly1305::new(&key_array);
        
        Ok(Self {
            inner,
            key: key.clone(),
        })
    }
    
    fn encrypt<'a>(&'a self) -> impl AeadEncryptionBuilder<'a, Self::Algorithm> {
        ChaCha20Poly1305EncryptionBuilder {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }
    
    fn decrypt<'a>(&'a self) -> impl AeadDecryptionBuilder<'a, Self::Algorithm> {
        ChaCha20Poly1305DecryptionBuilder {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }
    
    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key> {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        Ok(SecretBytes::new(key))
    }
    
    fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Nonce12> {
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        Ok(Nonce12::new(nonce))
    }
}

/// ChaCha20-Poly1305 encryption builder
#[cfg(feature = "alloc")]
pub struct ChaCha20Poly1305EncryptionBuilder<'a> {
    cipher: &'a ChaCha20Poly1305Cipher,
    nonce: Option<&'a Nonce12>,
    aad: Option<&'a [u8]>,
}

#[cfg(feature = "alloc")]
impl<'a> Builder<Vec<u8>> for ChaCha20Poly1305EncryptionBuilder<'a> {
    fn build(self) -> Result<Vec<u8>> {
        Err(Error::InvalidParameter("Use encrypt method instead"))
    }
    
    fn reset(&mut self) {
        self.nonce = None;
        self.aad = None;
    }
}

#[cfg(feature = "alloc")]
impl<'a> AeadEncryptionBuilder<'a, ChaCha20Poly1305Algorithm> 
    for ChaCha20Poly1305EncryptionBuilder<'a> 
{
    fn with_nonce(mut self, nonce: &'a Nonce12) -> Self {
        self.nonce = Some(nonce);
        self
    }
    
    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }
    
    fn encrypt(self, plaintext: &'a [u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce.ok_or_else(|| Error::InvalidParameter("Nonce is required"))?;
        
        // Convert nonce to array
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce.as_ref());
        
        self.cipher.inner.encrypt(
            &nonce_array,
            plaintext,
            self.aad,
        )
    }
}

/// ChaCha20-Poly1305 decryption builder
#[cfg(feature = "alloc")]
pub struct ChaCha20Poly1305DecryptionBuilder<'a> {
    cipher: &'a ChaCha20Poly1305Cipher,
    nonce: Option<&'a Nonce12>,
    aad: Option<&'a [u8]>,
}

#[cfg(feature = "alloc")]
impl<'a> Builder<Vec<u8>> for ChaCha20Poly1305DecryptionBuilder<'a> {
    fn build(self) -> Result<Vec<u8>> {
        Err(Error::InvalidParameter("Use decrypt method instead"))
    }
    
    fn reset(&mut self) {
        self.nonce = None;
        self.aad = None;
    }
}

#[cfg(feature = "alloc")]
impl<'a> AeadDecryptionBuilder<'a, ChaCha20Poly1305Algorithm> 
    for ChaCha20Poly1305DecryptionBuilder<'a> 
{
    fn with_nonce(mut self, nonce: &'a Nonce12) -> Self {
        self.nonce = Some(nonce);
        self
    }
    
    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }
    
    fn decrypt(self, ciphertext: &'a [u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce.ok_or_else(|| Error::InvalidParameter("Nonce is required"))?;
        
        // Convert nonce to array
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce.as_ref());
        
        self.cipher.inner.decrypt(
            &nonce_array,
            ciphertext,
            self.aad,
        )
    }
}