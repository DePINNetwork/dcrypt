//! Error types for the cryptographic primitives

#[cfg(feature = "std")]
use std::fmt::{self, Display};

/// Error type for cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Authentication failed during decryption
    AuthenticationFailed,
    
    /// Invalid input parameters (e.g., key size, nonce size)
    InvalidParameter(&'static str),
    
    /// Buffer is too small to hold the output
    BufferTooSmall { needed: usize, available: usize },
    
    /// Input data has invalid length
    InvalidLength { context: &'static str, needed: usize, got: usize },
    
    /// The primitive is not yet implemented
    NotImplemented(&'static str),
    
    /// Internal error
    InternalError(&'static str),
}

#[cfg(feature = "std")]
impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AuthenticationFailed => write!(f, "Authentication failed"),
            Error::InvalidParameter(desc) => write!(f, "Invalid parameter: {}", desc),
            Error::BufferTooSmall { needed, available } => {
                write!(f, "Buffer too small: needed {} bytes, but only {} available", needed, available)
            }
            Error::InvalidLength { context, needed, got } => {
                write!(f, "Invalid length for {}: needed {} bytes, got {}", context, needed, got)
            }
            Error::NotImplemented(feature) => write!(f, "Feature not implemented: {}", feature),
            Error::InternalError(desc) => write!(f, "Internal error: {}", desc),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for cryptographic operations
pub type Result<T> = core::result::Result<T, Error>;