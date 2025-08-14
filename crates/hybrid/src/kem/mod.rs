// File: crates/hybrid/src/kem/mod.rs

//! Hybrid Key Encapsulation Mechanisms (KEMs).
//!
//! This module provides KEMs that combine a classical primitive (like ECDH)
//! with a post-quantum primitive (like Kyber) to provide security against
//! both classical and quantum adversaries.

// Internal modules
mod engine;
mod traits;

// Concrete hybrid KEM implementations
mod ecdh_p256_kyber_768; 
mod ecdh_p384_kyber_1024;

// Tests
#[cfg(test)]
mod tests;

// Re-export the primary hybrid KEM structs for easy access.
pub use ecdh_p256_kyber_768::EcdhP256Kyber768;
pub use ecdh_p384_kyber_1024::EcdhP384Kyber1024;