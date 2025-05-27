//! Error handling for PKE operations.
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;
use api::error::Error as CoreError;
use algorithms::error::Error as PrimitiveError;

// Ensure String and format! are available for no_std + alloc
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::string::{String, ToString};
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::format;


/// Error type for PKE operations.
#[derive(Debug)]
pub enum Error {
    Primitive(PrimitiveError),
    Api(CoreError),
    InvalidCiphertextFormat(&'static str),
    EncryptionFailed(&'static str),
    DecryptionFailed(&'static str),
    KeyDerivationFailed(&'static str),
    UnsupportedOperation(&'static str),
    SerializationError(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Primitive(e) => write!(f, "PKE primitive error: {}", e),
            Error::Api(e) => write!(f, "PKE API error: {}", e),
            Error::InvalidCiphertextFormat(reason) => write!(f, "Invalid PKE ciphertext format: {}", reason),
            Error::EncryptionFailed(reason) => write!(f, "PKE encryption failed: {}", reason),
            Error::DecryptionFailed(reason) => write!(f, "PKE decryption failed: {}", reason),
            Error::KeyDerivationFailed(reason) => write!(f, "PKE key derivation failed: {}", reason),
            Error::UnsupportedOperation(op) => write!(f, "PKE unsupported operation: {}", op),
            Error::SerializationError(reason) => write!(f, "PKE internal serialization error: {}", reason),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Primitive(e) => Some(e),
            Error::Api(e) => Some(e),
            _ => None,
        }
    }
}

impl From<PrimitiveError> for Error {
    fn from(err: PrimitiveError) -> Self {
        Error::Primitive(err)
    }
}

impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        Error::Api(err)
    }
}

// Conversion from PKE Error to API Error
impl From<Error> for CoreError {
    fn from(err: Error) -> Self {
        match err {
            Error::Primitive(e) => e.into(),
            Error::Api(e) => e,
            Error::InvalidCiphertextFormat(reason) => CoreError::InvalidCiphertext {
                context: "ECIES",
                #[cfg(feature = "std")]
                message: reason.to_string(),
            },
            Error::EncryptionFailed(reason) => CoreError::Other {
                context: "ECIES Encryption",
                #[cfg(feature = "std")]
                message: reason.to_string(),
            },
            Error::DecryptionFailed(reason) => CoreError::DecryptionFailed {
                context: "ECIES Decryption",
                #[cfg(feature = "std")]
                message: reason.to_string(),
            },
            Error::KeyDerivationFailed(reason) => CoreError::Other {
                context: "ECIES KDF",
                #[cfg(feature = "std")]
                message: reason.to_string(),
            },
            Error::UnsupportedOperation(op) => CoreError::NotImplemented {
                feature: op,
            },
            Error::SerializationError(reason) => CoreError::SerializationError {
                context: "ECIES Internal",
                #[cfg(feature = "std")]
                message: reason.to_string(),
            }
        }
    }
}

/// Result type for PKE operations.
pub type Result<T> = core::result::Result<T, Error>;