//! Hash function implementations
//!
//! This module contains implementations of various cryptographic hash functions
//! used throughout the DCRYPT library.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub mod sha2;
pub mod sha3;
pub mod shake;

// Re-exports
pub use sha2::{Sha224, Sha256, Sha384, Sha512};
pub use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
pub use shake::{Shake128, Shake256};

/// Hash function result
pub type Hash = Vec<u8>;

/// Trait for cryptographic hash functions
pub trait HashFunction {
    /// Creates a new instance of the hash function
    fn new() -> Self;
    
    /// Updates the hash function state with new data
    fn update(&mut self, data: &[u8]);
    
    /// Finalizes the hash computation and returns the digest
    fn finalize(&mut self) -> Hash;
    
    /// Returns the output size of the hash function in bytes
    fn output_size() -> usize;
    
    /// Returns the block size of the hash function in bytes
    fn block_size() -> usize;
    
    /// Convenience method to hash data in a single call
    fn digest(data: &[u8]) -> Hash where Self: Sized {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
    
    /// Returns the name of the hash function
    fn name() -> &'static str;
}