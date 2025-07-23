//! Key Encapsulation Mechanisms (KEM) and Key Exchange
//!
//! This crate implements various key encapsulation mechanisms and key exchange
//! protocols, both traditional and post-quantum.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod error;
pub mod dh;
pub mod ecdh;
pub mod kyber;
pub mod saber;
pub mod mceliece;

// Re-exports
pub use dh::Dh2048;
pub use ecdh::{EcdhP192, EcdhP224, EcdhP256, EcdhP384, EcdhP521}; // Added EcdhP192
pub use kyber::{Kyber512, Kyber768, Kyber1024};
pub use saber::{LightSaber, Saber, FireSaber};
pub use mceliece::{McEliece348864, McEliece6960119};