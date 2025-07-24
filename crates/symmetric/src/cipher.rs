//! Symmetric cipher traits for dcrypt-symmetric
//!
//! This module defines the core traits used by all symmetric
//! encryption algorithms in the library.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::error::Result;

/// Common trait for all symmetric encryption algorithms
pub trait SymmetricCipher {
    /// The key type used by this cipher
    type Key;

    /// Creates a new cipher instance with the given key
    fn new(key: &Self::Key) -> Result<Self>
    where
        Self: Sized;

    /// Returns the name of this cipher
    fn name() -> &'static str;
}

/// Trait for Authenticated Encryption with Associated Data
pub trait Aead: SymmetricCipher {
    /// The nonce/IV type used by this cipher
    type Nonce;

    /// Encrypts plaintext with associated data
    fn encrypt(&self, nonce: &Self::Nonce, plaintext: &[u8], aad: Option<&[u8]>)
        -> Result<Vec<u8>>;

    /// Decrypts ciphertext with associated data
    /// Returns an error if authentication fails
    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Generates a secure random nonce
    fn generate_nonce() -> Self::Nonce;
}
