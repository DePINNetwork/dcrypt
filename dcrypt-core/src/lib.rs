//! Core functionality and shared traits for the DCRYPT library
//!
//! This crate provides the fundamental traits, error types, and utilities
//! shared across all other crates in the DCRYPT library.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

pub mod traits;
pub mod util;
pub mod error;
pub mod types;
pub mod security;

// Common mathematical operations
pub mod math_common;
mod ec_common;
mod ntru_common;
mod mceliece_common;

// Public re-exports
pub use error::{Error, Result};
pub use traits::*;
pub use types::*;

#[cfg(feature = "alloc")]
pub use security::SecretVec;

pub use security::{
    SecretBuffer, EphemeralSecret, ZeroizeGuard,
    SecureZeroingType, SecureOperation, SecureCompare,
};

// Re-export error validation utilities for ease of use
pub use error::validate;

// Re-export error handling traits
pub use error::traits::{ResultExt, SecureErrorHandling, ConstantTimeResult};