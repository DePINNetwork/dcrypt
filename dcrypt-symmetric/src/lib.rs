// File: dcrypt-symmetric/src/lib.rs
//! Symmetric encryption algorithms for the DCRYPT library
//!
//! This crate provides high-level symmetric encryption algorithms built on top of
//! the primitives in dcrypt-primitives.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod aes;
pub mod aead;
pub mod cipher;
pub mod error;
pub mod streaming;

// Re-export main types for convenience
pub use aes::{Aes128Key, Aes256Key};
pub use aead::gcm::{Aes128Gcm, Aes256Gcm, GcmNonce, AesCiphertextPackage};
pub use aead::chacha20poly1305::{
    ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher,
    ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, ChaCha20Poly1305CiphertextPackage,
    derive_chacha20poly1305_key, generate_salt,
    XChaCha20Poly1305Nonce
};
pub use cipher::{SymmetricCipher, Aead};
pub use error::{Error, Result};