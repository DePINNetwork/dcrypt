use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cryptographic error: {0}")]
    CryptoError(String),

    #[error("authentication failed")]
    AuthenticationError,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("key derivation failed")]
    KeyDerivationFailed,

    #[error("invalid format")]
    InvalidFormat,

    #[error("invalid key size")]
    InvalidKeySize,

    #[error("stream already finalized")]
    StreamAlreadyFinalized,

    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("invalid length for {context}: needed {needed}, got {got}")]
    InvalidLength { context: String, needed: usize, got: usize },

    #[error("internal error: {0}")]
    InternalError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<dcrypt_primitives::error::Error> for Error {
    fn from(err: dcrypt_primitives::error::Error) -> Self {
        match err {
            dcrypt_primitives::error::Error::InvalidLength { context, needed, got } =>
                Error::InvalidLength { 
                    context: context.to_string(), // Convert &str to String
                    needed, 
                    got 
                },
            dcrypt_primitives::error::Error::InvalidParameter(msg) =>
                Error::InvalidParameter(msg.to_string()), // Convert &str to String
            dcrypt_primitives::error::Error::AuthenticationFailed =>
                Error::AuthenticationError,
            dcrypt_primitives::error::Error::NotImplemented(feature) =>
                Error::InternalError(format!("{} is not implemented", feature)),
            dcrypt_primitives::error::Error::Other(msg) |
            dcrypt_primitives::error::Error::MacError(msg) =>
                Error::CryptoError(msg.to_string()), // Convert &str to String
            dcrypt_primitives::error::Error::InternalError(msg) =>
                Error::InternalError(msg.to_string()), // Convert &str to String
        }
    }
}
