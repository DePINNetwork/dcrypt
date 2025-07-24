//! # dcrypt
//! 
//! A modular cryptographic library providing both traditional and post-quantum algorithms.
//! 
//! ## Usage
//! 
//! Add this to your `Cargo.toml`:
//! 
//! ```toml
//! [dependencies]
//! dcrypt = "0.1"
//! ```
//! 
//! ## Features
//! 
//! - `traditional` (default): Traditional cryptographic algorithms
//! - `post-quantum`: Post-quantum cryptographic algorithms  
//! - `hybrid`: Hybrid constructions combining traditional and post-quantum
//! - `full`: All features enabled
//! 
//! ## Crate Structure
//! 
//! This is a facade crate that re-exports functionality from several sub-crates:
//! 
//! - [`dcrypt-algorithms`]: Core algorithms (AES, SHA, etc.)
//! - [`dcrypt-symmetric`]: Symmetric encryption
//! - [`dcrypt-kem`]: Key Encapsulation Mechanisms
//! - [`dcrypt-sign`]: Digital signatures
//! - [`dcrypt-pke`]: Public Key Encryption
//! - [`dcrypt-hybrid`]: Hybrid constructions

#![cfg_attr(not(feature = "std"), no_std)]

// Core re-exports (always available)
pub use dcrypt_api as api;
pub use dcrypt_common as common;
pub use dcrypt_internal as internal;
pub use dcrypt_params as params;

// Feature-gated re-exports
#[cfg(feature = "algorithms")]
pub use dcrypt_algorithms as algorithms;

#[cfg(feature = "symmetric")] 
pub use dcrypt_symmetric as symmetric;

#[cfg(feature = "kem")]
pub use dcrypt_kem as kem;

#[cfg(feature = "sign")]
pub use dcrypt_sign as sign;

#[cfg(feature = "pke")]
pub use dcrypt_pke as pke;

#[cfg(feature = "hybrid")]
pub use dcrypt_hybrid as hybrid;

/// Common imports for dcrypt users
pub mod prelude {
    // Re-export error types
    pub use crate::api::{Error, Result};
    
    // Re-export core traits
    pub use crate::api::{
        Kem,
        Signature,
        SymmetricCipher,
        Serialize,
        BlockCipher,
        StreamCipher,
        AuthenticatedCipher,
        KeyDerivationFunction,
        HashAlgorithm,
    };
    
    // Re-export security types
    pub use crate::common::{
        SecretBuffer,
        EphemeralSecret,
        ZeroizeGuard,
        SecureZeroingType,
    };
    
    // Re-export memory safety utilities
    pub use crate::common::{
        SecureOperation,
        SecureCompare,
        SecureOperationExt,
    };
    
    // Conditional re-exports based on features
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub use crate::common::SecureOperationBuilder;
    
    #[cfg(feature = "alloc")]
    pub use crate::common::SecretVec;
    
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub use crate::common::{ECPoint, CurveParams};
}