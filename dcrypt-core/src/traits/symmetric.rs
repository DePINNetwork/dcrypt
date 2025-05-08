//! Trait definition for symmetric encryption algorithms with enhanced type safety

use crate::error::Result;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Base trait for operation builders
pub trait Builder<T> {
    /// Execute the operation and produce a result
    fn build(self) -> Result<T>;
}

/// Base trait for encryption operation builders
pub trait EncryptionBuilder<'a, C: SymmetricCipher + ?Sized>: Builder<C::Ciphertext> {
    /// Set the nonce for encryption
    fn with_nonce(self, nonce: &'a C::Nonce) -> Self;
    
    /// Set associated data for authenticated encryption
    fn with_aad(self, aad: &'a [u8]) -> Self;
    
    /// Set plaintext and execute encryption
    fn encrypt(self, plaintext: &'a [u8]) -> Result<C::Ciphertext>;
}

/// Base trait for decryption operation builders
pub trait DecryptionBuilder<'a, C: SymmetricCipher + ?Sized>: Builder<Vec<u8>> {
    /// Set the nonce for decryption
    fn with_nonce(self, nonce: &'a C::Nonce) -> Self;
    
    /// Set associated data for authenticated decryption
    fn with_aad(self, aad: &'a [u8]) -> Self;
    
    /// Set ciphertext and execute decryption
    fn decrypt(self, ciphertext: &'a C::Ciphertext) -> Result<Vec<u8>>;
}

/// Trait for symmetric encryption algorithms with enhanced type safety
pub trait SymmetricCipher: Sized {
    /// Key type with appropriate algorithm binding
    type Key: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Nonce type with appropriate size constraint
    type Nonce: AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Ciphertext output type
    type Ciphertext: AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Builder type for encryption operations
    type EncryptionBuilder<'a>: EncryptionBuilder<'a, Self> where Self: 'a;
    
    /// Builder type for decryption operations 
    type DecryptionBuilder<'a>: DecryptionBuilder<'a, Self> where Self: 'a;
    
    /// Returns the symmetric cipher algorithm name
    fn name() -> &'static str;
    
    /// Begin encryption operation
    fn encrypt<'a>(&'a self) -> Self::EncryptionBuilder<'a>;
    
    /// Begin decryption operation
    fn decrypt<'a>(&'a self) -> Self::DecryptionBuilder<'a>;
    
    /// Generate a new random key
    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key>;
    
    /// Generate a new random nonce
    fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Nonce>;
    
    /// Derive a key from arbitrary bytes
    fn derive_key_from_bytes(bytes: &[u8]) -> Result<Self::Key>;
}