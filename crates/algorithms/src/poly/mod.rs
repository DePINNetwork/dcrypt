//! Generic Polynomial Engine
//!
//! This module provides foundational elements for polynomial arithmetic over rings,
//! designed to be reusable by various lattice-based cryptographic schemes.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod ntt;
pub mod params;
pub mod polynomial;
pub mod sampling;
pub mod serialize;

/// Prelude for easy importing of common polynomial types and traits.
pub mod prelude {
    pub use super::ntt::{montgomery_reduce, InverseNttOperator, NttOperator}; // FIXED: No NttModulus from ntt
    pub use super::params::{Modulus, NttModulus}; // FIXED: Export NttModulus only from params
    pub use super::polynomial::{Polynomial, PolynomialNttExt};
    pub use super::sampling::{CbdSampler, GaussianSampler, UniformSampler};
    pub use super::serialize::{CoefficientPacker, CoefficientUnpacker};
}

// Helper functions or common constants might be added here later.
