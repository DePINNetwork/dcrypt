//! ECDSA signature implementations for NIST curves
//!
//! This module provides secure implementations of the Elliptic Curve Digital
//! Signature Algorithm (ECDSA) using NIST P-256 and P-384 curves.

pub mod common;
pub mod p256;
pub mod p384;

// Re-export P-256 types
pub use p256::{
    EcdsaP256,
    EcdsaP256PublicKey,
    EcdsaP256SecretKey,
    EcdsaP256Signature
};

// Re-export P-384 types
pub use p384::{
    EcdsaP384,
    EcdsaP384PublicKey,
    EcdsaP384SecretKey,
    EcdsaP384Signature
};
