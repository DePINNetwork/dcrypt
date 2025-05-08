//! Type-safe salt implementation with validation
//!
//! Provides the `Salt` type, representing a cryptographic
//! salt with appropriate validation and randomization capabilities.

use rand::{CryptoRng, RngCore};
use core::fmt;
use core::ops::{Deref, DerefMut};
use zeroize::Zeroize;

use dcrypt_core::error::{DcryptError, Result};
use dcrypt_core::types::SecretVec;
use crate::types::{ConstantTimeEq, RandomGeneration, ByteSerializable};

/// A cryptographic salt with validation
#[derive(Clone, Zeroize)]
pub struct Salt {
    data: Vec<u8>,
    min_size: usize,
}

impl Salt {
    /// Recommended minimum salt size (16 bytes)
    pub const RECOMMENDED_MIN_SIZE: usize = 16;
    
    /// Create a new salt with the given minimum size
    pub fn new(data: Vec<u8>, min_size: Option<usize>) -> Result<Self> {
        let min_size = min_size.unwrap_or(Self::RECOMMENDED_MIN_SIZE);
        
        if data.len() < min_size {
            return Err(DcryptError::InvalidLength {
                context: "Salt::new",
                expected: min_size,
                actual: data.len(),
            });
        }
        
        Ok(Self { data, min_size })
    }
    
    /// Create from a slice, if it meets the minimum size requirement
    pub fn from_slice(slice: &[u8], min_size: Option<usize>) -> Result<Self> {
        Self::new(slice.to_vec(), min_size)
    }
    
    /// Get the minimum size required for this salt
    pub fn min_size(&self) -> usize {
        self.min_size
    }
    
    /// Get the length of the salt
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the salt is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Generate a random salt with the specified size
    pub fn random_with_size<R: RngCore + CryptoRng>(rng: &mut R, size: usize) -> Result<Self> {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        Self::new(data, Some(size))
    }
}

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for Salt {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Deref for Salt {
    type Target = Vec<u8>;
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for Salt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl PartialEq for Salt {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for Salt {}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Salt({})", self.data.len())
    }
}

impl ConstantTimeEq for Salt {
    fn ct_eq(&self, other: &Self) -> bool {
        dcrypt_core::util::constant_time::ct_eq(&self.data, &other.data)
    }
}

impl RandomGeneration for Salt {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        Self::random_with_size(rng, Self::RECOMMENDED_MIN_SIZE)
    }
}

impl ByteSerializable for Salt {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes, None)
    }
}