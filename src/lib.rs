//! dcrypt - A comprehensive cryptography library for DePIN Network's Web4 infrastructure
//! 
//! # Examples
//! 
//! ## Using AES-GCM
//! ```
//! use dcrypt::aead::{Aes256Gcm, Aead};
//! 
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let plaintext = b"Hello, World!";
//! 
//! let cipher = Aes256Gcm::new(&key);
//! let ciphertext = cipher.encrypt(&nonce, plaintext, None).unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Re-export all modules with clean organization
pub use algorithms::{
    aead, block, hash, kdf, mac, stream, xof,
    ec, poly, types as algo_types,
};

pub use symmetric::{
    cipher,
    aead as symmetric_aead,
    streaming,
};

pub mod kem {
    pub use kem::*;
}

pub mod sign {
    pub use sign::*;
}

pub mod pke {
    pub use pke::*;
}

pub mod hybrid {
    pub use hybrid::*;
}

// Common types at root level for convenience
pub use api::{
    Error, Result,
    traits::{Kem, Sign, Pke},
};

pub use common::{
    security::{SecretBuffer, SecretVec},
};

// Re-export important types from params
pub use params;

// Prelude for common imports
pub mod prelude {
    pub use crate::{Error, Result};
    pub use crate::aead::Aead;
    pub use crate::hash::HashFunction;
    pub use crate::mac::Mac;
    pub use crate::kdf::Kdf;
}