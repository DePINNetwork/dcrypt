//! Error types for symmetric encryption

/// Represents errors that can occur during symmetric encryption and decryption
#[derive(Debug)]
pub enum Error {
    /// Error during cryptographic operation
    CryptoError(&'static str),
    /// Authentication failed during decryption
    AuthenticationError,
    /// IO error occurred
    IoError,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Invalid format for serialized data
    InvalidFormat,
    /// Invalid key size
    InvalidKeySize,
    /// Stream already finalized
    StreamAlreadyFinalized,
    /// Invalid parameter
    InvalidParameter(&'static str),
    /// Invalid length
    InvalidLength {
        context: &'static str,
        needed: usize,
        got: usize,
    },
    /// Internal error with a descriptive message
    InternalError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            Error::AuthenticationError => write!(f, "Authentication failed"),
            Error::IoError => write!(f, "IO error"),
            Error::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Error::InvalidFormat => write!(f, "Invalid format"),
            Error::InvalidKeySize => write!(f, "Invalid key size"),
            Error::StreamAlreadyFinalized => write!(f, "Stream already finalized"),
            Error::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            Error::InvalidLength { context, needed, got } => {
                write!(f, "Invalid length for {}: needed {}, got {}", context, needed, got)
            },
            Error::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Result type for symmetric encryption operations
pub type Result<T> = std::result::Result<T, Error>;