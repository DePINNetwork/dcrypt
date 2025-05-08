//! Operations for Key Derivation Function (KDF) operations
//!
//! This module provides operation implementations for key derivation operations
//! with proper parameter validation and fluent APIs.

use crate::error::{Error, Result};
use crate::operation::{Operation, WithOutputLength, WithData};
use std::marker::PhantomData;

/// Common trait for KDF operations
pub trait KdfOperation {
    /// Salt type (may be fixed or variable length)
    type Salt: AsRef<[u8]>;
    
    /// Info type for context and application data
    type Info: AsRef<[u8]>;
    
    /// Default output size in bytes
    const DEFAULT_OUTPUT_SIZE: usize;
    
    /// Minimum recommended salt size in bytes
    const MIN_SALT_SIZE: usize;
    
    /// Algorithm name
    fn algorithm_name() -> &'static str;
}

/// Builder for KDF operations
pub struct KdfBuilder<'a, T: KdfOperation> {
    /// Optional input keying material
    ikm: Option<&'a [u8]>,
    
    /// Optional salt
    salt: Option<&'a T::Salt>,
    
    /// Optional info/context
    info: Option<&'a T::Info>,
    
    /// Output length
    output_length: usize,
    
    /// Phantom data for type parameter
    _phantom: PhantomData<T>,
}

impl<'a, T: KdfOperation> KdfBuilder<'a, T> {
    /// Create a new KDF builder
    pub fn new() -> Self {
        Self {
            ikm: None,
            salt: None,
            info: None,
            output_length: T::DEFAULT_OUTPUT_SIZE,
            _phantom: PhantomData,
        }
    }
    
    /// Set the salt for this operation
    pub fn with_salt(mut self, salt: &'a T::Salt) -> Self {
        self.salt = Some(salt);
        self
    }
    
    /// Set the info/context for this operation
    pub fn with_info(mut self, info: &'a T::Info) -> Self {
        self.info = Some(info);
        self
    }
    
    /// Derive a key using the configured parameters
    ///
    /// This method consumes the builder and produces a derived key.
    pub fn derive(self) -> Result<Vec<u8>> {
        // Validate that all required parameters are set
        let ikm = self.ikm.ok_or_else(|| Error::InvalidParameter(
            "Input keying material is required for key derivation"
        ))?;
        
        // Validate output length if needed
        if self.output_length == 0 {
            return Err(Error::InvalidParameter(
                "Output length must be greater than zero"
            ));
        }
        
        // This is a placeholder - in an actual implementation,
        // this would call the algorithm-specific key derivation method
        Err(Error::NotImplemented(
            "KDF implementation"
        ))
    }
    
    /// Derive a key into a fixed-size array
    ///
    /// This method is a convenience wrapper around `derive` that produces
    /// a fixed-size array to avoid unnecessary allocations.
    pub fn derive_array<const N: usize>(self) -> Result<[u8; N]> {
        // First ensure the output length matches the array size
        if self.output_length != N {
            return Err(Error::InvalidLength {
                context: "KDF output",
                needed: N,
                got: self.output_length,
            });
        }
        
        // Then derive the key as a vector
        let key_vec = self.derive()?;
        
        // Convert the vector to a fixed-size array
        let mut result = [0u8; N];
        result.copy_from_slice(&key_vec);
        Ok(result)
    }
}

impl<'a, T: KdfOperation> Default for KdfBuilder<'a, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T: KdfOperation> Operation<Vec<u8>> for KdfBuilder<'a, T> {
    fn execute(self) -> Result<Vec<u8>> {
        self.derive()
    }
    
    fn reset(&mut self) {
        self.ikm = None;
        self.salt = None;
        self.info = None;
        self.output_length = T::DEFAULT_OUTPUT_SIZE;
    }
}

impl<'a, T: KdfOperation> WithOutputLength<Self> for KdfBuilder<'a, T> {
    fn with_output_length(mut self, length: usize) -> Self {
        self.output_length = length;
        self
    }
}

impl<'a, T: KdfOperation> WithData<'a, Self> for KdfBuilder<'a, T> {
    fn with_data(mut self, data: &'a [u8]) -> Self {
        self.ikm = Some(data);
        self
    }
}