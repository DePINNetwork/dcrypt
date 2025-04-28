//! Block cipher implementations
//!
//! This module contains implementations of various block ciphers and related
//! algorithms.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use zeroize::Zeroize;

pub mod aes;
pub mod modes;

// Re-exports
pub use aes::{Aes128, Aes192, Aes256};
pub use modes::{Cbc, Ctr};

/// Trait for block ciphers
pub trait BlockCipher {
    /// Block size in bytes
    const BLOCK_SIZE: usize;
    
    /// Creates a new block cipher instance with the given key
    fn new(key: &[u8]) -> Self;
    
    /// Encrypts a single block in place
    fn encrypt_block(&self, block: &mut [u8]);
    
    /// Decrypts a single block in place
    fn decrypt_block(&self, block: &mut [u8]);
    
    /// Returns the key size in bytes
    fn key_size() -> usize;
    
    /// Returns the block size in bytes
    fn block_size() -> usize {
        Self::BLOCK_SIZE
    }
    
    /// Returns the name of the block cipher
    fn name() -> &'static str;
}

/// Trait for authenticated block cipher modes
pub trait AuthenticatedCipher: Sized {
    /// Creates a new authenticated cipher instance
    fn new(key: &[u8], nonce: &[u8]) -> Self;
    
    /// Encrypts the plaintext with the additional authenticated data
    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Vec<u8>;
    
    /// Decrypts the ciphertext with the additional authenticated data
    fn decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, ()>;
    
    /// Returns the key size in bytes
    fn key_size() -> usize;
    
    /// Returns the nonce size in bytes
    fn nonce_size() -> usize;
    
    /// Returns the tag size in bytes
    fn tag_size() -> usize;
    
    /// Returns the name of the authenticated cipher mode
    fn name() -> &'static str;
}