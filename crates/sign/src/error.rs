//! Error types for the signature crate

use core::fmt;

/// Errors that can occur during signature operations
#[derive(Debug, Clone)]
pub enum Error {
    /// Algorithm not supported
    Algorithm(String),
    
    /// Invalid key size
    InvalidKeySize { expected: usize, actual: usize },
    
    /// Invalid signature size
    InvalidSignatureSize { expected: usize, actual: usize },
    
    /// Invalid parameter
    InvalidParameter(String),
    
    /// Invalid key
    InvalidKey(String),
    
    /// Key generation failed
    KeyGeneration { algorithm: &'static str, details: String },
    
    /// Signature generation failed
    SignatureGeneration { algorithm: &'static str, details: String },
    
    /// Verification failed
    Verification { algorithm: &'static str, details: String },
    
    /// Encoding error
    Encoding(String),
    
    /// Deserialization error
    Deserialization(String),
    
    /// Serialization error
    Serialization(String),
    
    /// Nonce error
    Nonce(String),
    
    /// Hashing error
    Hashing(String),
    
    /// RNG error
    Rng(String),
    
    /// Sampling error
    Sampling(String),
    
    /// Internal error
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Algorithm(alg) => write!(f, "Unsupported algorithm: {}", alg),
            Error::InvalidKeySize { expected, actual } => {
                write!(f, "Invalid key size: expected {}, got {}", expected, actual)
            }
            Error::InvalidSignatureSize { expected, actual } => {
                write!(f, "Invalid signature size: expected {}, got {}", expected, actual)
            }
            Error::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            Error::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            Error::KeyGeneration { algorithm, details } => {
                write!(f, "{} key generation failed: {}", algorithm, details)
            }
            Error::SignatureGeneration { algorithm, details } => {
                write!(f, "{} signature generation failed: {}", algorithm, details)
            }
            Error::Verification { algorithm, details } => {
                write!(f, "{} verification failed: {}", algorithm, details)
            }
            Error::Encoding(msg) => write!(f, "Encoding error: {}", msg),
            Error::Deserialization(msg) => write!(f, "Deserialization error: {}", msg),
            Error::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            Error::Nonce(msg) => write!(f, "Nonce error: {}", msg),
            Error::Hashing(msg) => write!(f, "Hashing error: {}", msg),
            Error::Rng(msg) => write!(f, "RNG error: {}", msg),
            Error::Sampling(msg) => write!(f, "Sampling error: {}", msg),
            Error::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

// Helper method to convert from algorithms error
impl Error {
    pub fn from_algo(err: algorithms::error::Error) -> Self {
        Self::Internal(format!("Algorithm error: {:?}", err))
    }
}

// Convert from algorithms::error::Error
impl From<algorithms::error::Error> for Error {
    fn from(err: algorithms::error::Error) -> Self {
        use algorithms::error::Error as AlgoError;
        
        match err {
            AlgoError::Parameter { name, reason } => {
                Error::InvalidParameter(format!("{}: {}", name, reason))
            }
            AlgoError::NotImplemented { feature } => {
                Error::Internal(format!("Feature not implemented: {}", feature))
            }
            _ => Error::Internal(format!("Algorithm error: {:?}", err)),
        }
    }
}

// Convert to api::Error  
impl From<Error> for api::Error {
    fn from(err: Error) -> Self {
        match err {
            // Map Algorithm error to InvalidParameter with context
            Error::Algorithm(alg) => api::Error::InvalidParameter {
                context: "algorithm".into(),
                message: format!("Unsupported algorithm: {}", alg),
            },
            Error::InvalidKeySize { expected, actual } => api::Error::InvalidKey {
                context: "sign".into(),
                message: format!("Invalid key size: expected {}, got {}", expected, actual),
            },
            Error::InvalidSignatureSize { expected, actual } => api::Error::InvalidSignature {
                context: "sign".into(),
                message: format!("Invalid signature size: expected {}, got {}", expected, actual),
            },
            Error::InvalidParameter(msg) => api::Error::InvalidParameter {
                context: "sign".into(),
                message: msg,
            },
            Error::InvalidKey(msg) => api::Error::InvalidKey {
                context: "sign".into(),
                message: msg,
            },
            // Map KeyGeneration to InvalidKey (key generation failures produce invalid keys)
            Error::KeyGeneration { algorithm, details } => api::Error::InvalidKey {
                context: algorithm.into(),
                message: format!("Key generation failed: {}", details),
            },
            // Map SignatureGeneration to InvalidSignature
            Error::SignatureGeneration { algorithm, details } => api::Error::InvalidSignature {
                context: algorithm.into(),
                message: format!("Signature generation failed: {}", details),
            },
            Error::Verification { algorithm, details } => api::Error::InvalidSignature {
                context: algorithm.into(),
                message: details,
            },
            Error::Encoding(s) => api::Error::InvalidParameter {
                context: "encoding".into(),
                message: s,
            },
            Error::Deserialization(s) => api::Error::InvalidParameter {
                context: "deserialization".into(),
                message: s,
            },
            Error::Serialization(s) => api::Error::InvalidParameter {
                context: "serialization".into(),
                message: s,
            },
            Error::Nonce(s) => api::Error::InvalidParameter {
                context: "nonce".into(),
                message: s,
            },
            // Map internal errors (Hashing, Rng, Sampling, Internal) to InvalidParameter
            // This isn't ideal but without an Internal variant in api::Error, this is the best mapping
            Error::Hashing(s) => api::Error::InvalidParameter {
                context: "hashing".into(),
                message: s,
            },
            Error::Rng(s) => api::Error::InvalidParameter {
                context: "rng".into(),
                message: s,
            },
            Error::Sampling(s) => api::Error::InvalidParameter {
                context: "sampling".into(),
                message: s,
            },
            Error::Internal(s) => api::Error::InvalidParameter {
                context: "internal".into(),
                message: s,
            },
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;