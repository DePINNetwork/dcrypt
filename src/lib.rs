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
//! dcrypt = "0.9.0-beta.3"
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
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! // Using through the main crate
//! use dcrypt::api::Signature;
//! use dcrypt::sign::dilithium::{DilithiumSigningKey, DilithiumVerifyingKey};
//! 
//! // Or using the prelude
//! use dcrypt::prelude::*;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

// Core re-exports (always available)
pub use dcrypt_api as api;
pub use dcrypt_common as common;
pub use dcrypt_internal as internal;
pub use dcrypt_params as params;

// Re-export commonly used items from api at the crate root for convenience
pub use api::{Error, Result};

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

// Re-export commonly used traits at the crate root for easier access
#[cfg(feature = "sign")]
pub use api::Signature;

// Also re-export the traits module for direct trait access
pub use api::traits;

/// Common imports for dcrypt users
pub mod prelude {
    // Re-export error types
    pub use crate::api::{Error, Result};

    // Re-export core traits from api
    pub use crate::api::{
        AuthenticatedCipher, BlockCipher, HashAlgorithm, Kem, KeyDerivationFunction, Serialize,
        Signature, StreamCipher, SymmetricCipher,
    };
    
    // Re-export all traits from api::traits if they exist
    pub use crate::api::traits::*;

    // Re-export security types
    pub use crate::common::{EphemeralSecret, SecretBuffer, SecureZeroingType, ZeroizeGuard};

    // Re-export memory safety utilities
    pub use crate::common::{SecureCompare, SecureOperation, SecureOperationExt};

    // Conditional re-exports based on features
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub use crate::common::SecureOperationBuilder;

    #[cfg(feature = "alloc")]
    pub use crate::common::SecretVec;

    #[cfg(any(feature = "std", feature = "alloc"))]
    pub use crate::common::{CurveParams, ECPoint};
    
    // Feature-specific trait re-exports
    #[cfg(feature = "kem")]
    pub use crate::kem::{KemCiphertext, KemPublicKey, KemSecretKey, SharedSecret};
    
    #[cfg(feature = "sign")]
    pub use crate::sign::{SigningKey, VerifyingKey};
    
    #[cfg(feature = "pke")]
    pub use crate::pke::{Ciphertext, Plaintext, PublicKey, SecretKey};
}

// Test that imports work correctly
#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "sign")]
    fn test_sign_imports() {
        // This should compile if the imports are working
        use crate::api::Signature as SignatureTrait;
        use crate::sign;
        
        // Type annotations to ensure we can access the module
        let _: Option<&dyn SignatureTrait> = None;
    }
    
    #[test] 
    #[cfg(feature = "full")]
    fn test_full_imports() {
        // Test that all modules are accessible with full features
        use crate::{algorithms, api, common, hybrid, internal, kem, params, pke, sign, symmetric};
        
        // Just checking that the modules exist
        let _ = api::Error;
    }
}