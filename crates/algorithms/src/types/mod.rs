//! Type-safe wrappers for cryptographic types
//!
//! This module provides domain-specific types with compile-time and runtime
//! guarantees for cryptographic operations, designed to be ergonomic while
//! preventing common mistakes.

// Submodules
pub mod algorithms;
pub mod digest;
pub mod key;
pub mod nonce;
pub mod salt;
pub mod tag;

// Sealed trait module (not public)
pub(crate) mod sealed;

// Re-export main types
pub use nonce::Nonce;
pub use salt::Salt;
pub use digest::Digest;
pub use tag::Tag;
pub use key::{SymmetricKey, AsymmetricSecretKey, AsymmetricPublicKey};

// Import and re-export core types
pub use api::types::{SecretBytes, SecretVec, Key, Ciphertext};

// Import and re-export security types from dcrypt-core
pub use common::security::{
    SecretBuffer, 
    EphemeralSecret, 
    ZeroizeGuard,
    SecureZeroingType,  // Use the trait from core
};

/// Marker trait for validating symmetric key sizes for specific algorithms.
/// 
/// This trait ensures that a symmetric key type has a valid size for the
/// specified algorithm. It's sealed to prevent external implementations.
pub trait ValidKeySize<A: key::SymmetricAlgorithm, const N: usize>: sealed::Sealed {}

/// Marker trait for validating asymmetric secret key sizes for specific algorithms.
/// 
/// This trait ensures that an asymmetric secret key type has a valid size for the
/// specified algorithm. It's sealed to prevent external implementations.
pub trait ValidSecretKeySize<A: key::AsymmetricAlgorithm, const N: usize>: sealed::Sealed {}

/// Marker trait for validating asymmetric public key sizes for specific algorithms.
/// 
/// This trait ensures that an asymmetric public key type has a valid size for the
/// specified algorithm. It's sealed to prevent external implementations.
pub trait ValidPublicKeySize<A: key::AsymmetricAlgorithm, const N: usize>: sealed::Sealed {}

// Common cryptographic traits
use rand::{CryptoRng, RngCore};

/// Trait for cryptographic types with constant-time equality
pub trait ConstantTimeEq {
    /// Compare two values in constant time
    fn ct_eq(&self, other: &Self) -> bool;
}

/// Trait for cryptographic types that can be randomly generated
pub trait RandomGeneration: Sized {
    /// Generate a random instance using the provided RNG
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> crate::error::Result<Self>;
}

/// Trait for types that have a fixed size
pub trait FixedSize {
    /// Get the size in bytes
    fn size() -> usize;
}

/// Trait for types that can be serialized to a byte representation
pub trait ByteSerializable: Sized {
    /// Convert to a byte vector
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Try to create from a byte slice
    fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self>;
}

/// Trait for types compatible with algorithms that have specific size requirements
pub trait AlgorithmCompatible<A> {}

// Re-export algorithm compatibility traits from submodules
pub use nonce::{
    ChaCha20Compatible,
    XChaCha20Compatible,
    AesGcmCompatible,
    AesCtrCompatible,
};

pub use salt::{
    Pbkdf2Compatible,
    Argon2Compatible,
    HkdfCompatible,
};

pub use digest::{
    Sha256Compatible,
    Sha512Compatible,
    Blake2bCompatible,
};

pub use tag::{
    Poly1305Compatible,
    HmacCompatible,
    GcmCompatible,
    ChaCha20Poly1305Compatible,
};

// Re-export algorithm marker types
#[cfg(feature = "ec")] // Guard these EC related algo markers
pub use algorithms::{
    Ed25519, X25519, P256, P384, P521, // Added NIST curves
};

pub use algorithms::{ // These are generally always available or controlled by other features
    Aes128, Aes256, ChaCha20, ChaCha20Poly1305,
};

// Re-export key algorithm traits
pub use key::{SymmetricAlgorithm, AsymmetricAlgorithm};

// Re-export key type aliases for convenience
pub use algorithms::{
    // Symmetric keys
    Aes128Key, Aes256Key, ChaCha20Key, ChaCha20Poly1305Key,
    // Asymmetric keys
    Ed25519SecretKey, Ed25519PublicKey,
    X25519SecretKey, X25519PublicKey,
    P256SecretKey, P256PublicKeyUncompressed, P256PublicKeyCompressed,
    P384SecretKey, P384PublicKeyUncompressed, P384PublicKeyCompressed,
    P521SecretKey, P521PublicKeyUncompressed, P521PublicKeyCompressed,
};