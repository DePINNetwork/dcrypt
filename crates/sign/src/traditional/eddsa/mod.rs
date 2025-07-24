//! EdDSA (Edwards-curve Digital Signature Algorithm) implementations
//!
//! This module provides a production-ready implementation of Ed25519,
//! the most widely used EdDSA variant, as specified in RFC 8032.
//!
//! # Features
//!
//! - Full Ed25519 signature scheme with actual curve arithmetic
//! - Deterministic signature generation
//! - Constant-time operations where applicable
//! - Secure key generation and handling
//! - Comprehensive input validation
//!
//! # Example
//!
//! ```
//! use dcrypt_sign::traditional::eddsa::Ed25519;
//! use dcrypt_api::Signature;
//! use rand::rngs::OsRng;
//!
//! # fn main() -> dcrypt_api::Result<()> {
//! let mut rng = OsRng;
//! let (public_key, secret_key) = Ed25519::keypair(&mut rng)?;
//!
//! let message = b"Hello, Ed25519!";
//! let signature = Ed25519::sign(message, &secret_key)?;
//!
//! assert!(Ed25519::verify(message, &signature, &public_key).is_ok());
//! # Ok(())
//! # }
//! ```

mod constants;
mod ed25519;
mod field;
mod operations;
mod point;
mod scalar;

// Re-export Ed25519 types
pub use ed25519::{Ed25519, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

// The curve arithmetic modules are internal and not exported.
// They provide the mathematical operations needed by Ed25519.
