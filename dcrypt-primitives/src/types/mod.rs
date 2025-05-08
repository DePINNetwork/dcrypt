//! Type-safe wrappers for cryptographic types
//!
//! This module provides domain-specific types with compile-time and runtime
//! guarantees for cryptographic operations, designed to be ergonomic while
//! preventing common mistakes.

// Re-export submodules
pub mod nonce;
pub mod salt;
pub mod digest;
pub mod key;
pub mod tag;
pub mod algorithms;

// Re-export common types
pub use nonce::Nonce;
pub use salt::Salt;
pub use digest::Digest;
pub use key::{SymmetricKey, AsymmetricSecretKey, AsymmetricPublicKey};
pub use dcrypt_core::types::Key;
pub use tag::Tag;
pub use algorithms::*;

// Import and re-export core types
pub use dcrypt_core::types::{SecretBytes, SecretVec};

/// Trait for cryptographic types with constant-time equality
pub trait ConstantTimeEq {
    /// Compare two values in constant time
    fn ct_eq(&self, other: &Self) -> bool;
}

/// Trait for cryptographic types that can be randomly generated
pub trait RandomGeneration: Sized {
    /// Generate a random instance using the provided RNG
    fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> dcrypt_core::error::Result<Self>;
}

/// Trait for types that can be securely zeroed
pub trait SecureZeroingType: Sized + zeroize::Zeroize {
    /// Create a new zeroed instance
    fn zeroed() -> Self;
}

/// Trait for types that have a fixed size
pub trait FixedSize {
    /// Get the size in bytes
    fn size() -> usize;
}

/// Trait for types that can be serialized to a byte representation
pub trait ByteSerializable: Sized {
    /// Convert to a byte array
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Try to create from a byte array
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self>;
}