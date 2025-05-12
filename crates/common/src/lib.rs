//! Common implementations and shared functionality for the DCRYPT library
//!
//! This crate provides common utilities and implementations used across
//! multiple DCRYPT components.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

pub mod security;
pub mod math_common;
pub mod ec_common;
pub mod ntru_common;
pub mod mceliece_common;

// Re-export core security types
pub use security::{
    SecretBuffer, 
    EphemeralSecret, 
    ZeroizeGuard,
    SecureZeroingType,
};

// Conditionally re-export SecretVec only when alloc feature is enabled
#[cfg(feature = "alloc")]
pub use security::secret::SecretVec;

// Re-export memory safety traits and utilities
pub use security::memory::{
    SecureOperation, 
    SecureCompare, 
    SecureOperationExt,
    SecureOperationBuilder,
};

// Re-export memory barrier utilities
pub use security::memory::barrier;