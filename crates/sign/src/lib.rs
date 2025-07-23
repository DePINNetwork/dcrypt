//! Digital Signature Schemes
//!
//! This crate implements various digital signature schemes,
//! both traditional and post-quantum.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod traditional;
pub mod pq;
pub mod error;

// Re-exports from traditional schemes
pub use traditional::eddsa::Ed25519;
pub use traditional::ecdsa::{EcdsaP192, EcdsaP256, EcdsaP384, EcdsaP521};

// Re-exports from post-quantum schemes
pub use pq::dilithium::{Dilithium2, Dilithium3, Dilithium5};
pub use pq::falcon::{Falcon512, Falcon1024};
pub use pq::sphincs::{SphincsSha2, SphincsShake};
pub use pq::rainbow::{RainbowI, RainbowIII, RainbowV};