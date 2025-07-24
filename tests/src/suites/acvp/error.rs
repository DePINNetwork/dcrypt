// tests/src/suites/acvp/error.rs
//! Structured error types for ACVP engine

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("crypto operation failed: {0}")]
    Crypto(String),

    #[error("unsupported key size: {0} bytes")]
    KeySize(usize),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("mismatch - expected: {expected}, got: {actual}")]
    Mismatch { expected: String, actual: String },

    #[error("invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;

// Helper for converting algorithm errors
impl From<dcrypt_algorithms::error::Error> for EngineError {
    fn from(e: dcrypt_algorithms::error::Error) -> Self {
        EngineError::Crypto(e.to_string())
    }
}

// Implement From<api::Error> for EngineError
impl From<dcrypt_api::error::Error> for EngineError {
    fn from(api_err: dcrypt_api::error::Error) -> Self {
        // Convert api::Error to a String and then into EngineError::Crypto
        // This is a general conversion. Specific mappings could be added if needed.
        EngineError::Crypto(api_err.to_string())
    }
}

// Implement From<sign::error::Error> for EngineError
impl From<dcrypt_sign::error::Error> for EngineError {
    fn from(sign_err: dcrypt_sign::error::Error) -> Self {
        // Convert sign::Error to EngineError::Crypto
        EngineError::Crypto(sign_err.to_string())
    }
}
