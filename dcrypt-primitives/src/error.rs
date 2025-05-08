//! Error types and result definitions for dcrypt-primitives
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

use core::fmt;
use dcrypt_core::error::{DcryptError, Result as CoreResult};

/// The error type for dcrypt-primitives
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A value had an invalid length.
    InvalidLength {
        /// What was being checked (e.g. "GCM ciphertext")
        context: &'static str,
        /// How many bytes were required
        needed: usize,
        /// How many bytes were provided
        got: usize,
    },
    /// A parameter was invalid (e.g. bad tag length, bad nonce length).
    InvalidParameter(&'static str),
    /// Authentication (e.g. AEAD tag verification) failed.
    AuthenticationFailed,
    /// A feature or function is not yet implemented.
    NotImplemented(&'static str),
    /// A generic error with a static message.
    Other(&'static str),
    /// An internal error (e.g. stub or unimplemented functionality).
    InternalError(&'static str),
    /// Message authentication code (MAC) processing error.
    MacError(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength { context, needed, got } => {
                write!(f, "{}: invalid length (need {}, got {})", context, needed, got)
            }
            Error::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            Error::AuthenticationFailed => write!(f, "Authentication failed"),
            Error::NotImplemented(feature) => write!(f, "{} is not implemented", feature),
            Error::Other(msg) => write!(f, "{}", msg),
            Error::InternalError(msg) => write!(f, "Internal error: {}", msg),
            Error::MacError(msg) => write!(f, "MAC error: {}", msg),
        }
    }
}

// Implement std::error::Error when std is available
#[cfg(feature = "std")]
impl std::error::Error for Error {}

// Implement conversion to DcryptError
impl From<Error> for DcryptError {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidLength { context, needed, got } => DcryptError::InvalidLength {
                context,
                expected: needed,
                actual: got,
            },
            Error::InvalidParameter(msg) => DcryptError::InvalidParameter {
                context: "parameter validation",
                #[cfg(feature = "std")]
                message: msg.to_string(),
            },
            Error::AuthenticationFailed => DcryptError::AuthenticationFailed {
                context: "authentication",
            },
            Error::NotImplemented(feature) => DcryptError::NotImplemented {
                feature,
            },
            Error::Other(msg) => DcryptError::Other {
                context: "primitive operation",
                #[cfg(feature = "std")]
                message: msg.to_string(),
            },
            Error::InternalError(msg) => DcryptError::Other {
                context: "internal error",
                #[cfg(feature = "std")]
                message: msg.to_string(),
            },
            Error::MacError(msg) => DcryptError::Other {
                context: "MAC operation",
                #[cfg(feature = "std")]
                message: msg.to_string(),
            },
        }
    }
}

/// A specialized `Result` type for dcrypt-primitives.
pub type Result<T> = core::result::Result<T, Error>;

/// Convert a primitives result to a core result with additional context
pub fn to_core_result<T>(result: Result<T>, context: &'static str) -> CoreResult<T> {
    result.map_err(|e| {
        let core_err = DcryptError::from(e);
        core_err.with_context(context)
    })
}