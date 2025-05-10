// dcrypt-symmetric/src/error/validate.rs
//! Validation utilities for symmetric cryptographic operations

use super::{Error, Result};

/// Validate stream operation
pub fn stream(condition: bool, operation: &'static str, details: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::Stream { operation, details });
    }
    Ok(())
}

/// Validate format/serialization
pub fn format(condition: bool, context: &'static str, details: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::Format { context, details });
    }
    Ok(())
}

/// Validate key derivation parameters
pub fn key_derivation(condition: bool, algorithm: &'static str, details: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::KeyDerivation { algorithm, details });
    }
    Ok(())
}

// Re-export primitive validations for convenience
pub use dcrypt_primitives::error::validate::{
    parameter,
    length,
    min_length,
    max_length,
    authentication,
};