//! Common utilities for key derivation functions

#![cfg_attr(not(feature = "std"), no_std)]

// Conditional imports for different platforms
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// Use appropriate RNG implementation based on platform
#[cfg(feature = "std")]
use rand::{rngs::OsRng, RngCore};

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

impl SecurityLevel {
    /// Get the security level in bits
    pub fn bits(&self) -> u32 {
        match self {
            SecurityLevel::L128 => 128,
            SecurityLevel::L192 => 192,
            SecurityLevel::L256 => 256,
            SecurityLevel::Custom(bits) => *bits,
        }
    }
    
    /// Get the recommended output size in bytes for this security level
    pub fn recommended_output_size(&self) -> usize {
        // For KDFs, output size is typically twice the security level
        // to account for birthday attacks
        (self.bits() / 4) as usize
    }
    
    /// Check if this security level meets a minimum requirement
    pub fn meets_minimum(&self, minimum: SecurityLevel) -> bool {
        self.bits() >= minimum.bits()
    }
}

/// Compare two slices in constant time
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Generate a random salt of the given length (standard library version)
#[cfg(feature = "std")]
pub fn generate_salt(len: usize) -> Zeroizing<Vec<u8>> {
    let mut salt = vec![0u8; len];
    OsRng.fill_bytes(&mut salt);
    Zeroizing::new(salt)
}

/// Generate a random salt of the given length (embedded version)
/// 
/// Note: This requires a custom RNG implementation for embedded platforms
#[cfg(all(feature = "alloc", not(feature = "std"), not(target_arch = "wasm32")))]
pub fn generate_salt(len: usize) -> Zeroizing<Vec<u8>> {
    // NOTE: In a real embedded implementation, you would need to provide
    // a cryptographically secure RNG here. This is a placeholder.
    let mut salt = vec![0u8; len];
    
    // TODO: Replace with actual embedded RNG implementation
    // For now, this just returns zeroed memory which is NOT secure
    // Example: embedded_rng::fill_bytes(&mut salt);
    
    Zeroizing::new(salt)
}

/// Generate a random salt of the given length (WASM version)
#[cfg(all(feature = "alloc", target_arch = "wasm32", not(feature = "std")))]
pub fn generate_salt(len: usize) -> Zeroizing<Vec<u8>> {
    let mut salt = vec![0u8; len];
    
    // For WASM, we can use getrandom which works in browser environments
    getrandom::getrandom(&mut salt).expect("Failed to generate random bytes");
    
    Zeroizing::new(salt)
}
