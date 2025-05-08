//! Error types for the DCRYPT library with enhanced context preservation

#[cfg(feature = "std")]
use thiserror::Error;

/// Result type for DCRYPT operations
pub type Result<T> = core::result::Result<T, DcryptError>;

/// Error type for DCRYPT operations
#[cfg(feature = "std")]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DcryptError {
    /// Invalid key error
    #[error("Invalid key: {context}")]
    InvalidKey {
        context: &'static str,
    },

    /// Invalid signature error
    #[error("Invalid signature: {context}")]
    InvalidSignature {
        context: &'static str,
    },

    /// Decryption error
    #[error("Decryption failed: {context}")]
    DecryptionFailed {
        context: &'static str,
    },

    /// Invalid ciphertext error
    #[error("Invalid ciphertext: {context}")]
    InvalidCiphertext {
        context: &'static str,
    },
    
    /// Invalid length error with context
    #[error("{context}: invalid length (expected {expected}, got {actual})")]
    InvalidLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    
    /// Invalid parameter error
    #[error("{context}: {message}")]
    InvalidParameter {
        context: &'static str,
        message: String,
    },
    
    /// Serialization error
    #[error("Serialization error: {context}: {message}")]
    SerializationError {
        context: &'static str,
        message: String,
    },
    
    /// Random generation error
    #[error("Random generation error: {context}")]
    RandomGenerationError {
        context: &'static str,
    },
    
    /// Not implemented error
    #[error("{feature} is not implemented")]
    NotImplemented {
        feature: &'static str,
    },
    
    /// Authentication failed error
    #[error("Authentication failed: {context}")]
    AuthenticationFailed {
        context: &'static str,
    },
    
    /// Other error
    #[error("{context}: {message}")]
    Other {
        context: &'static str,
        message: String,
    },
}

/// Error type for DCRYPT operations (no_std version)
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcryptError {
    /// Invalid key error
    InvalidKey {
        context: &'static str,
    },

    /// Invalid signature error
    InvalidSignature {
        context: &'static str,
    },

    /// Decryption error
    DecryptionFailed {
        context: &'static str,
    },

    /// Invalid ciphertext error
    InvalidCiphertext {
        context: &'static str,
    },
    
    /// Invalid length error with context
    InvalidLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    
    /// Invalid parameter error
    InvalidParameter {
        context: &'static str,
    },
    
    /// Serialization error
    SerializationError {
        context: &'static str,
    },
    
    /// Random generation error
    RandomGenerationError {
        context: &'static str,
    },
    
    /// Not implemented error
    NotImplemented {
        feature: &'static str,
    },
    
    /// Authentication failed error
    AuthenticationFailed {
        context: &'static str,
    },
    
    /// Other error
    Other {
        context: &'static str,
    },
}

impl DcryptError {
    /// Add context to an existing error
    pub fn with_context(self, context: &'static str) -> Self {
        match self {
            #[cfg(feature = "std")]
            Self::InvalidKey { .. } => Self::InvalidKey { context },
            #[cfg(feature = "std")]
            Self::InvalidSignature { .. } => Self::InvalidSignature { context },
            #[cfg(feature = "std")]
            Self::DecryptionFailed { .. } => Self::DecryptionFailed { context },
            #[cfg(feature = "std")]
            Self::InvalidCiphertext { .. } => Self::InvalidCiphertext { context },
            #[cfg(feature = "std")]
            Self::InvalidLength { expected, actual, .. } => Self::InvalidLength { 
                context, 
                expected, 
                actual 
            },
            #[cfg(feature = "std")]
            Self::InvalidParameter { message, .. } => Self::InvalidParameter { 
                context, 
                message 
            },
            #[cfg(feature = "std")]
            Self::SerializationError { message, .. } => Self::SerializationError { 
                context, 
                message 
            },
            #[cfg(feature = "std")]
            Self::RandomGenerationError { .. } => Self::RandomGenerationError { context },
            #[cfg(feature = "std")]
            Self::NotImplemented { feature } => Self::NotImplemented { feature },
            #[cfg(feature = "std")]
            Self::AuthenticationFailed { .. } => Self::AuthenticationFailed { context },
            #[cfg(feature = "std")]
            Self::Other { message, .. } => Self::Other { context, message },
            
            // no_std variants
            #[cfg(not(feature = "std"))]
            Self::InvalidKey { .. } => Self::InvalidKey { context },
            #[cfg(not(feature = "std"))]
            Self::InvalidSignature { .. } => Self::InvalidSignature { context },
            #[cfg(not(feature = "std"))]
            Self::DecryptionFailed { .. } => Self::DecryptionFailed { context },
            #[cfg(not(feature = "std"))]
            Self::InvalidCiphertext { .. } => Self::InvalidCiphertext { context },
            #[cfg(not(feature = "std"))]
            Self::InvalidLength { expected, actual, .. } => Self::InvalidLength { 
                context, 
                expected, 
                actual 
            },
            #[cfg(not(feature = "std"))]
            Self::InvalidParameter { .. } => Self::InvalidParameter { context },
            #[cfg(not(feature = "std"))]
            Self::SerializationError { .. } => Self::SerializationError { context },
            #[cfg(not(feature = "std"))]
            Self::RandomGenerationError { .. } => Self::RandomGenerationError { context },
            #[cfg(not(feature = "std"))]
            Self::NotImplemented { feature } => Self::NotImplemented { feature },
            #[cfg(not(feature = "std"))]
            Self::AuthenticationFailed { .. } => Self::AuthenticationFailed { context },
            #[cfg(not(feature = "std"))]
            Self::Other { .. } => Self::Other { context },
        }
    }
}

// Standard library error conversions
#[cfg(feature = "std")]
impl From<std::array::TryFromSliceError> for DcryptError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::InvalidLength {
            context: "array conversion",
            expected: 0,  // Unknown expected size
            actual: 0,    // Unknown actual size
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for DcryptError {
    fn from(e: std::io::Error) -> Self {
        Self::Other {
            context: "I/O operation",
            message: e.to_string(),
        }
    }
}

// Specialized result types for different operations
pub type CipherResult<T> = Result<T>;
pub type HashResult<T> = Result<T>;
pub type KeyResult<T> = Result<T>;
pub type SignatureResult<T> = Result<T>;