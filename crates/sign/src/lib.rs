//! Digital Signature Schemes
//!
//! This crate implements various digital signature schemes,
//! both traditional and post-quantum.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod traditional;
pub mod dilithium;
pub mod falcon;
pub mod sphincs;
pub mod rainbow;

// Re-exports
pub use traditional::ed25519::Ed25519;
pub use traditional::ecdsa::{EcdsaP256, EcdsaP384};
pub use traditional::rsa::{RsaPss, RsaPkcs1};
pub use traditional::dsa::Dsa;
pub use dilithium::{Dilithium2, Dilithium3, Dilithium5};
pub use falcon::{Falcon512, Falcon1024};
pub use sphincs::{SphincsSha2, SphincsShake};
pub use rainbow::{RainbowI, RainbowIII, RainbowV};
