//! Trait definition for symmetric encryption algorithms

use crate::error::Result;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Trait for symmetric encryption algorithms
pub trait SymmetricCipher {
    /// Key type
    type Key: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Nonce/IV type
    type Nonce: AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Returns the symmetric cipher algorithm name
    fn name() -> &'static str;
    
    /// Generate a new random key
    fn generate_key<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::Key>;
    
    /// Generate a new random nonce
    fn generate_nonce<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::Nonce>;
    
    /// Encrypt a message using the given key and nonce
    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    
    /// Decrypt a ciphertext using the given key and nonce
    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    
    /// Derive a key from arbitrary bytes
    fn derive_key_from_bytes(bytes: &[u8]) -> Result<Self::Key>;
}