//! Cryptographic primitives for the DCRYPT library
//!
//! This crate provides essential cryptographic primitives with strong type safety
//! guarantees through domain-specific types and operation patterns.

#![cfg_attr(not(feature = "std"), no_std)]

// Conditional imports based on features
#[cfg(any(feature = "std", feature = "alloc"))]
extern crate alloc;

// Core modules
pub mod error;
pub mod types;

// Operation pattern core traits
pub mod operations;

// Cryptographic primitive modules
#[cfg(any(feature = "block", feature = "std"))]
pub mod block;

#[cfg(any(feature = "hash", feature = "std"))]
pub mod hash;

#[cfg(any(feature = "mac", feature = "std"))]
pub mod mac;

#[cfg(any(feature = "stream", feature = "std"))]
pub mod stream;

#[cfg(any(feature = "aead", feature = "std"))]
pub mod aead;

#[cfg(any(feature = "xof", feature = "std"))]
pub mod xof;

#[cfg(any(feature = "kdf", feature = "std"))]
pub mod kdf;

// Re-export error types
pub use error::{Error, Result};

// Re-export common types for convenience
pub use types::{
    Nonce, Salt, Digest, Key, 
    Aes128Key, Aes256Key, ChaCha20Key, ChaCha20Poly1305Key,
};
pub use types::nonce::{Nonce12, Nonce16, Nonce24};
pub use types::digest::{Digest32, Digest64};

// Re-export operation traits for ergonomic usage
pub use operations::{
    Operation, WithData, WithNonce, WithAssociatedData, WithOutputLength,
    aead::{AeadEncryptOperation, AeadDecryptOperation},
    kdf::KdfOperation
};

// Re-export algorithm implementations
#[cfg(feature = "aead")]
pub use aead::{
    chacha20poly1305::ChaCha20Poly1305,
    xchacha20poly1305::XChaCha20Poly1305,
    gcm::Gcm,
};

#[cfg(feature = "hash")]
pub use hash::{
    sha2::{Sha256, Sha384, Sha512},
    sha3::{Sha3_256, Sha3_384, Sha3_512},
    blake2::{Blake2b, Blake2s},
};

#[cfg(feature = "kdf")]
pub use kdf::{
    hkdf::Hkdf,
    pbkdf2::{Pbkdf2, Pbkdf2Params},
    argon2::{Argon2, Argon2Params},
};

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");