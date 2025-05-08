//! Extendable Output Functions (XOF)
//!
//! This module contains implementations of Extendable Output Functions (XOFs)
//! which can produce outputs of arbitrary length.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(not(feature = "std"))]
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use crate::error::{Error, Result};

#[cfg(feature = "alloc")]
pub mod shake;

#[cfg(feature = "alloc")]
pub mod blake3;

// Re-exports
#[cfg(feature = "alloc")]
pub use shake::{ShakeXof128, ShakeXof256};

#[cfg(feature = "alloc")]
pub use blake3::Blake3Xof;

/// An Extendable Output Function (XOF) produces output of arbitrary length
#[cfg(feature = "alloc")]
pub type Xof = Vec<u8>;

/// Trait for extendable output functions
pub trait ExtendableOutputFunction {
    /// Creates a new instance of the XOF
    fn new() -> Self;

    /// Updates the XOF state with new data
    fn update(&mut self, data: &[u8]) -> Result<()>;

    /// Finalizes the XOF state for output
    fn finalize(&mut self) -> Result<()>;

    /// Squeezes output bytes into the provided buffer
    fn squeeze(&mut self, output: &mut [u8]) -> Result<()>;

    /// Squeezes the specified number of output bytes into a new vector
    #[cfg(feature = "alloc")]
    fn squeeze_into_vec(&mut self, len: usize) -> Result<Vec<u8>>;

    /// Resets the XOF state
    fn reset(&mut self) -> Result<()>;

    /// Returns the security level in bits
    fn security_level() -> usize;

    /// Convenience method to generate output in a single call
    #[cfg(feature = "alloc")]
    fn generate(data: &[u8], len: usize) -> Result<Vec<u8>>
    where
        Self: Sized,
    {
        let mut xof = Self::new();
        xof.update(data)?;
        xof.squeeze_into_vec(len)
    }
}