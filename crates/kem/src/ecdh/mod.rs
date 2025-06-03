// File: crates/kem/src/ecdh/mod.rs
//! ECDH-KEM implementations for NIST curves
//!
//! This module provides constant-time implementations of ECDH-KEM
//! using the NIST P-192, P-224, P-256, P-384, and P-521 curves, // Added P-192
//! following standard practices for key encapsulation mechanisms.

pub mod p192; // Added P-192 module
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521; 

// Re-export the P-192 types // Added P-192 exports
pub use p192::{
    EcdhP192,
    EcdhP192PublicKey,
    EcdhP192SecretKey,
    EcdhP192SharedSecret,
    EcdhP192Ciphertext
};

// Re-export the P-224 types
pub use p224::{
    EcdhP224,
    EcdhP224PublicKey,
    EcdhP224SecretKey,
    EcdhP224SharedSecret,
    EcdhP224Ciphertext
};

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