//! Cryptographic primitives for the DCRYPT library
//!
//! This crate provides essential cryptographic primitives such as hash functions,
//! extendable output functions (XOFs), and block ciphers that serve as building 
//! blocks for higher-level cryptographic algorithms.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod hash;
pub mod aead;
pub mod xof;
pub mod block;
pub mod error;
pub mod stream;
pub mod mac;

#[cfg(feature = "std")]

// Re-export commonly used items
pub use hash::{Hash, HashFunction};
pub use xof::{Xof, ExtendableOutputFunction};
pub use block::{BlockCipher, AuthenticatedCipher};
pub use aead::gcm::Gcm; 
pub use error::{Error, Result};