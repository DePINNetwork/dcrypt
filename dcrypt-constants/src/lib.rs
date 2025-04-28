//! Centralized algorithm parameters and constants for DCRYPT
//!
//! This crate provides constants required for cryptographic algorithms,
//! including key sizes, modulus values, and algorithm-specific parameters.

#![cfg_attr(not(feature = "std"), no_std)]

// Traditional algorithm constants
pub mod traditional;

// Post-quantum algorithm constants
pub mod pqc;

// Utility constants
pub mod utils;