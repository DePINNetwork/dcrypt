//! Validation utilities for KEM operations

use super::{Error, Result};

/// Validate key pair generation parameters
pub fn key_generation(condition: bool, algorithm: &'static str, details: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::KeyGeneration { algorithm, details });
    }
    Ok(())
}

/// Validate encapsulation parameters
pub fn encapsulation(condition: bool, algorithm: &'static str, details: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::Encapsulation { algorithm, details });
    }
    Ok(())
}

/// Validate decapsulation parameters
pub fn decapsulation(condition: bool, algorithm: &'static str, details: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::Decapsulation { algorithm, details });
    }
    Ok(())
}

/// Validate key format
pub fn key(condition: bool, key_type: &'static str, reason: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::InvalidKey { key_type, reason });
    }
    Ok(())
}

/// Validate ciphertext format
pub fn ciphertext(condition: bool, algorithm: &'static str, reason: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::InvalidCiphertext { algorithm, reason });
    }
    Ok(())
}

/// Validate serialization format
pub fn serialization(condition: bool, context: &'static str, details: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::Serialization { context, details });
    }
    Ok(())
}

// Re-export primitive validations for convenience
pub use dcrypt_api::error::validate::{
    parameter,
    length,
    min_length,
    max_length,
};