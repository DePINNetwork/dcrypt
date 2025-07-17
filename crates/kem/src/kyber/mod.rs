// kem/src/kyber/mod.rs

//! Kyber Key Encapsulation Mechanism (KEM).
//!
//! This module implements Kyber KEM, a lattice-based key encapsulation mechanism
//! selected for standardization by NIST. It provides IND-CCA2 security.

// Modules defining the Kyber KEM logic and parameters.
mod params;
mod polyvec;        // Defines PolyVec and its operations
mod serialize;      // Serialization functions for Kyber data structures
mod cpa_pke;        // Defines the core CPA-secure PKE scheme
mod ind_cca;        // Implements the Fujisaki-Okamoto transform for CCA security
mod kem;            // Defines the KyberKem struct and implements api::Kem

// Concrete Kyber variants
mod kyber512;
mod kyber768;
mod kyber1024;

// Re-export the primary KEM types for each security level.
pub use self::kyber512::Kyber512;
pub use self::kyber768::Kyber768;
pub use self::kyber1024::Kyber1024;

// Re-export common key/ciphertext types if users need to name them directly.
// These are generic over the KyberParams, so usually users will interact
// via the associated types of Kyber512, Kyber768, Kyber1024.
pub use self::kem::{KyberPublicKey, KyberSecretKey, KyberCiphertext, KyberSharedSecret};

// Re-export important constants that external modules might need
pub use self::params::KYBER_SS_BYTES;

#[cfg(test)]
mod tests;