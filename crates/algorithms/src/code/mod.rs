//! Code-Based Cryptography Primitives
//!
//! This module is a placeholder for mathematical primitives required by
//! code-based cryptosystems like Classic McEliece.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod sparse_matrix;

// pub use sparse_matrix::SparseBinaryMatrix;
// Might also include modules for:
// - Goppa codes
// - Syndrome decoding
// - Permutation generation
// - Polynomial arithmetic over GF(2^m)
