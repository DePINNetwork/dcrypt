//! DCRYPT: A pure Rust cryptographic library with both traditional and post-quantum algorithms
//!
//! This is the main crate that re-exports all cryptographic algorithms and provides
//! a high-level API for using them.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod kem;
pub mod sign;

/// Re-exports commonly used items
pub mod prelude {
    pub use dcrypt_core::{DcryptError, Result, Kem, Signature, SymmetricCipher, Serialize};
    pub use crate::kem::*;
    pub use crate::sign::*;
}

// Re-exports
pub use dcrypt_core as core;
pub use dcrypt_constants as constants;
pub use dcrypt_primitives as primitives;
pub use dcrypt_symmetric as symmetric;
pub use dcrypt_kem as kem_impl;
pub use dcrypt_sign as sign_impl;
pub use dcrypt_hybrid as hybrid;
pub use dcrypt_utils as util;
