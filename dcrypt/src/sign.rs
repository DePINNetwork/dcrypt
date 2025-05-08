//! Facade for signature algorithms
//!
//! This module re-exports all signature algorithms from dcrypt-sign and
//! provides a high-level interface for using them.

// Re-export traditional signatures
pub use dcrypt_sign::traditional::ed25519::Ed25519;
pub use dcrypt_sign::traditional::ecdsa::{EcdsaP256, EcdsaP384};
pub use dcrypt_sign::traditional::rsa::{RsaPss, RsaPkcs1};
pub use dcrypt_sign::traditional::dsa::Dsa;

// Re-export post-quantum signatures
pub use dcrypt_sign::dilithium::{Dilithium2, Dilithium3, Dilithium5};
pub use dcrypt_sign::falcon::{Falcon512, Falcon1024};
pub use dcrypt_sign::sphincs::{SphincsSha2, SphincsShake};
pub use dcrypt_sign::rainbow::{RainbowI, RainbowIII, RainbowV};

// Re-export hybrid signatures
pub use dcrypt_hybrid::sign::{EcdsaDilithiumHybrid, RsaFalconHybrid};
