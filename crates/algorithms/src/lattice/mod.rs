//! Lattice Cryptography Primitives
//!
//! This module serves as a convenient entry point for lattice-based cryptographic
//! schemes, primarily re-exporting the generic polynomial algebra engine.
//! It may later host lattice-specific constants or helper functions that
//! are not general enough for the `poly` module but are shared among
//! different lattice schemes (e.g., Ring-LWE, Module-LWE).

#![cfg_attr(not(feature = "std"), no_std)]

// Re-export all public items from the polynomial engine.
// Implementations will typically use `algorithms::lattice::Polynomial` etc.
pub use crate::poly::*;

// Example of a lattice-specific helper that might be added later:
//
// /// Performs Barrett reduction for a specific power-of-two modulus,
// /// often used in lattice cryptography for fast modular reduction.
// pub fn barrett_reduce_pow2(value: u64, q: u32, k: u32, precomputed_r: u64) -> u32 {
//     // q must be a power of two, k = log2(q)
//     // precomputed_r = floor(2^(k+s) / q) where s is a shift parameter.
//     // This is a conceptual placeholder.
//     (value - (((value * precomputed_r) >> (k + s)) * q)) as u32
// }
