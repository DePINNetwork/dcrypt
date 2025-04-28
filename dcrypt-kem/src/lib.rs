//! Key Encapsulation Mechanisms (KEM) and Key Exchange
//!
//! This crate implements various key encapsulation mechanisms and key exchange
//! protocols, both traditional and post-quantum.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod rsa;
pub mod dh;
pub mod ecdh;
pub mod kyber;
pub mod ntru;
pub mod saber;
pub mod mceliece;

// Re-exports
pub use rsa::{RsaKem2048, RsaKem4096};
pub use dh::Dh2048;
pub use ecdh::{EcdhP256, EcdhP384};
pub use kyber::{Kyber512, Kyber768, Kyber1024};
pub use ntru::{NtruHps, NtruEes};
pub use saber::{LightSaber, Saber, FireSaber};
pub use mceliece::{McEliece348864, McEliece6960119};
