//! Common utilities for key derivation functions

#![cfg_attr(not(feature = "std"), no_std)]

// Conditional imports for different platforms
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

// Use appropriate RNG implementation based on platform
#[cfg(feature = "std")]
use rand::{rngs::OsRng, RngCore};

#[cfg(all(not(feature = "std"), not(target_arch = "wasm32"), feature = "alloc"))]
use crate::embedded::rng;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Security level for KDFs in bits
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// 128-bit security level
    L128,
    /// 192-bit security level
    L192,
    /// 256-bit security level
    L256,
    /// Custom security level (in bits)
    Custom(u32),
}

/// Compare two slices in constant time
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Generate a random salt of the given length
#[cfg(feature = "std")]
pub fn generate_salt(len: usize) -> Zeroizing<Vec<u8>> {
    let mut salt = vec![0u8; len];
    OsRng.fill_bytes(&mut salt);
    Zeroizing::new(salt)
}

/// Generate a random salt of the given length (embedded version)
#[cfg(all(feature = "alloc", not(feature = "std"), not(target_arch = "wasm32")))]
pub fn generate_salt(len: usize) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(rng::generate_salt(len))
}