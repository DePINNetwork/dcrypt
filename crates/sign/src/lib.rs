//! Digital Signature Schemes
//!
//! This crate implements various digital signature schemes,
//! both traditional and post-quantum.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod error;
pub mod pq;
pub mod traditional;

// Re-exports from traditional schemes
pub use traditional::ecdsa::{EcdsaP192, EcdsaP256, EcdsaP384, EcdsaP521};
pub use traditional::eddsa::Ed25519;

// Re-exports from post-quantum schemes
pub use pq::dilithium::{Dilithium2, Dilithium3, Dilithium5};
pub use pq::falcon::{Falcon1024, Falcon512};
pub use pq::rainbow::{RainbowI, RainbowIII, RainbowV};
pub use pq::sphincs::{SphincsSha2, SphincsShake};
