//! Hybrid Key Encapsulation Mechanisms (KEMs).
//!
//! This module provides KEMs that combine a classical primitive (like ECDH)
//! with a post-quantum primitive (like Kyber) to provide security against
//! both classical and quantum adversaries.

pub mod ecdh_kyber;

#[cfg(test)]
mod tests;

// Re-export the primary hybrid KEM struct for easy access.
pub use ecdh_kyber::EcdhKyber768;