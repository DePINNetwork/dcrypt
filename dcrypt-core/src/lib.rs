//! Core functionality and shared traits for the DCRYPT library
//!
//! This crate provides the fundamental traits, error types, and utilities
//! shared across all other crates in the DCRYPT library.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod traits;
pub mod util;
pub mod error;
pub mod types;

// Common mathematical operations
pub mod math_common;
mod ec_common;
mod ntru_common;
mod mceliece_common;

// Public re-exports
pub use error::{DcryptError, Result};
pub use traits::*;
pub use types::*;