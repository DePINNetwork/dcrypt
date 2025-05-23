// File: crates/algorithms/src/ec/mod.rs
//! Elliptic Curve Primitives
//! 
//! This module provides constant-time implementations of elliptic curve operations
//! on NIST curves P-256 and P-384. These implementations are designed to be resistant
//! to timing attacks and provide a foundation for higher-level protocols like ECDH-KEM.

pub mod p256;
pub mod p384;

// Re-export common types
pub use p256::{Point as P256Point, Scalar as P256Scalar};
pub use p384::{Point as P384Point, Scalar as P384Scalar};

/// Common trait for coordinate systems used in elliptic curve operations
pub trait CoordinateSystem {}

/// Affine coordinates (x,y)
pub struct Affine;
impl CoordinateSystem for Affine {}

/// Jacobian projective coordinates (X:Y:Z) where x = X/Z² and y = Y/Z³
pub struct Jacobian;
impl CoordinateSystem for Jacobian {}