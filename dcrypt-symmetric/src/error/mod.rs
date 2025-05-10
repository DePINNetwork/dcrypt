// dcrypt-symmetric/src/error/mod.rs
//! Error handling for symmetric cryptographic operations

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std::string::String;

use core::fmt;
use dcrypt_core::error::{Error as CoreError, Result as CoreResult};
use dcrypt_primitives::error::Error as PrimitiveError;

/// Error type for symmetric cryptographic operations
#[derive(Debug, Clone)]
pub enum Error {
    /// Primitive error
    Primitive(PrimitiveError),
    
    /// Stream operation error
    Stream { 
        operation: &'static str,
        details: &'static str 
    },
    
    /// Format error (for base64, serialization, etc.)
    Format { 
        context: &'static str,
        details: &'static str 
    },
    
    /// Key derivation error  
    KeyDerivation { 
        algorithm: &'static str,
        details: &'static str 
    },
    
    /// I/O error (only when std is available)
    #[cfg(feature = "std")]
    Io(String),  // Changed from std::io::Error to String
}

/// Result type for symmetric operations
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Primitive(e) => write!(f, "Primitive error: {}", e),
            Error::Stream { operation, details } => {
                write!(f, "Stream {} error: {}", operation, details)
            },
            Error::Format { context, details } => {
                write!(f, "Format error in {}: {}", context, details)
            },
            Error::KeyDerivation { algorithm, details } => {
                write!(f, "Key derivation error for {}: {}", algorithm, details)
            },
            #[cfg(feature = "std")]
            Error::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

// Standard error trait
#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Primitive(e) => Some(e),
            _ => None,  // IO errors are now strings, so no source
        }
    }
}

// From PrimitiveError to Error
impl From<PrimitiveError> for Error {
    fn from(err: PrimitiveError) -> Self {
        Error::Primitive(err)
    }
}

// From CoreError to Error
impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::InvalidLength { context, expected, actual } => {
                Error::Format { 
                    context: "length validation", 
                    details: "invalid length" 
                }
            },
            CoreError::InvalidParameter { context, .. } => {
                Error::Format { 
                    context,
                    details: "invalid parameter" 
                }
            },
            // Map other core errors to format errors or wrap them as primitives
            _ => {
                // For now, we'll convert to a generic format error
                // This could be refined based on specific core error types
                Error::Format { 
                    context: "core operation", 
                    details: "operation failed" 
                }
            }
        }
    }
}

// From std::io::Error to Error (when std is available)
#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())  // Convert to string
    }
}

// From Error to CoreError
impl From<Error> for CoreError {
    fn from(err: Error) -> Self {
        match err {
            Error::Primitive(e) => e.into(),
            Error::Stream { operation, details } => CoreError::Other {
                context: operation,
                #[cfg(feature = "std")]
                message: details.to_string(),
            },
            Error::Format { context, details } => CoreError::SerializationError {
                context,
                #[cfg(feature = "std")]
                message: details.to_string(),
            },
            Error::KeyDerivation { algorithm, details } => CoreError::Other {
                context: algorithm,
                #[cfg(feature = "std")]
                message: format!("key derivation failed: {}", details),
            },
            #[cfg(feature = "std")]
            Error::Io(e) => CoreError::Other {
                context: "I/O operation",
                message: e,  // Already a string
            },
        }
    }
}

// Include validation submodule
pub mod validate;

// Re-export core error handling traits
pub use dcrypt_core::error::{ResultExt, SecureErrorHandling};