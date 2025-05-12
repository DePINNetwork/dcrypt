//! Public API traits and types for the DCRYPT library
//!
//! This crate provides the public API surface for the DCRYPT ecosystem, including
//! trait definitions, error types, and common types used throughout the library.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

pub mod traits;
pub mod error;
pub mod types;

// Re-export commonly used items at the crate level for convenience
pub use error::{Error, Result};
pub use types::*;

// Re-export all traits from the traits module
pub use traits::{
    Kem,
    Signature,
    SymmetricCipher,
    Serialize,
    BlockCipher,
    StreamCipher,
    AuthenticatedCipher,
    KeyDerivationFunction,
    HashAlgorithm,
};

// Re-export trait modules for direct access
pub use traits::{kem, signature, symmetric, serialize};