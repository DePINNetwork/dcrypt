//! Public Key Encryption (PKE) schemes for the DCRYPT library.
#![cfg_attr(not(feature = "std"), no_std)]

// Required for Vec, String, format! in no_std + alloc environments
// This makes the `alloc` crate available when the "alloc" feature of this crate ("pke") is enabled.
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

pub mod error;
pub mod ecies;

// Re-export key items
pub use error::{Error, Result};
pub use ecies::{EciesP256, EciesP384};