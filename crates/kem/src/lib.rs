//! Key Encapsulation Mechanisms (KEM) and Key Exchange
//!
//! This crate implements various key encapsulation mechanisms and key exchange
//! protocols, both traditional and post-quantum.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod dh;
pub mod ecdh;
pub mod error;
pub mod kyber;
pub mod mceliece;
pub mod saber;

// Re-exports
pub use dh::Dh2048;
pub use ecdh::{EcdhP192, EcdhP224, EcdhP256, EcdhP384, EcdhP521}; // Added EcdhP192
pub use kyber::{Kyber1024, Kyber512, Kyber768};
pub use mceliece::{McEliece348864, McEliece6960119};
pub use saber::{FireSaber, LightSaber, Saber};
