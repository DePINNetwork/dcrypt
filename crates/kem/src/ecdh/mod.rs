// File: crates/kem/src/ecdh/mod.rs
//! ECDH-KEM implementations for NIST curves
//!
//! This module provides constant-time implementations of ECDH-KEM
//! using the NIST P-256 and P-384 curves, following standard practices
//! for key encapsulation mechanisms.

pub mod p256;
pub mod p384;
pub mod p521; // Added P-521 module

// Re-export the P-256 types
pub use p256::{
    EcdhP256, 
    EcdhP256PublicKey, 
    EcdhP256SecretKey, 
    EcdhP256SharedSecret, 
    EcdhP256Ciphertext
};

// Re-export the P-384 types
pub use p384::{
    EcdhP384,
    EcdhP384PublicKey,
    EcdhP384SecretKey,
    EcdhP384SharedSecret,
    EcdhP384Ciphertext
};

// Re-export the P-521 types
pub use p521::{
    EcdhP521,
    EcdhP521PublicKey,
    EcdhP521SecretKey,
    EcdhP521SharedSecret,
    EcdhP521Ciphertext
};


// Version tag for KDF context - updated for compressed point format
pub(crate) const KEM_KDF_VERSION: &str = "v2.0.0";