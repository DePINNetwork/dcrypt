//! Error types for the DCRYPT library

#[cfg(feature = "std")]
use thiserror::Error;

/// Result type for DCRYPT operations
pub type Result<T> = core::result::Result<T, DcryptError>;

/// Error type for DCRYPT operations
#[cfg(feature = "std")]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DcryptError {
    /// Invalid key error
    #[error("Invalid key")]
    InvalidKey,

    /// Invalid signature error
    #[error("Invalid signature")]
    InvalidSignature,

    /// Decryption error
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Invalid ciphertext error
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    
    /// Invalid parameter error
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    /// Random generation error
    #[error("Random generation error")]
    RandomGenerationError,
    
    /// Not implemented error
    #[error("Not implemented")]
    NotImplemented,
    
    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// Error type for DCRYPT operations (no_std version)
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcryptError {
    /// Invalid key error
    InvalidKey,

    /// Invalid signature error
    InvalidSignature,

    /// Decryption error
    DecryptionFailed,

    /// Invalid ciphertext error
    InvalidCiphertext,
    
    /// Invalid parameter error
    InvalidParameter,
    
    /// Serialization error
    SerializationError,
    
    /// Random generation error
    RandomGenerationError,
    
    /// Not implemented error
    NotImplemented,
    
    /// Other error
    Other,
}