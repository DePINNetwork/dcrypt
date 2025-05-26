//! Traditional signature schemes
//!
//! This module contains implementations of traditional (pre-quantum) signature
//! schemes including ECDSA, EdDSA, and RSA.

pub mod dsa;
pub mod ecdsa;
pub mod eddsa;
pub mod rsa;

// Re-export DSA types
pub use dsa::Dsa;

// Re-export ECDSA types
pub use ecdsa::{
    EcdsaP256,
    EcdsaP256PublicKey,
    EcdsaP256SecretKey,
    EcdsaP256Signature,
    EcdsaP384,
    EcdsaP384PublicKey,
    EcdsaP384SecretKey,
    EcdsaP384Signature,
};

// Re-export EdDSA types
pub use eddsa::Ed25519;

// Re-export RSA types
pub use rsa::{RsaPss, RsaPkcs1};