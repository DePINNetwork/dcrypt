//! Type-safe authentication tag implementation with size guarantees
//!
//! Provides the `Tag` type, representing a cryptographic authentication tag
//! with compile-time size guarantees.

use core::fmt;
use core::ops::{Deref, DerefMut};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use dcrypt_core::error::{DcryptError, Result};
use crate::types::{ConstantTimeEq, RandomGeneration, SecureZeroingType, FixedSize, ByteSerializable};

/// A cryptographic authentication tag with fixed size
#[derive(Clone, Zeroize)]
pub struct Tag<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Tag<N> {
    /// Create a new tag from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }
    
    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(DcryptError::InvalidLength {
                context: "Tag::from_slice",
                expected: N,
                actual: slice.len(),
            });
        }
        
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        
        Ok(Self { data })
    }
    
    /// Get the length of the tag
    pub fn len(&self) -> usize {
        N
    }
    
    /// Check if the tag is empty
    pub fn is_empty(&self) -> bool {
        N == 0
    }
    
    /// Convert to a hexadecimal string
    pub fn to_hex(&self) -> String {
        let mut result = String::with_capacity(N * 2);
        for &byte in &self.data {
            result.push_str(&format!("{:02x}", byte));
        }
        result
    }
}

impl<const N: usize> AsRef<[u8]> for Tag<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for Tag<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Deref for Tag<N> {
    type Target = [u8; N];
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for Tag<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> PartialEq for Tag<N> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<const N: usize> Eq for Tag<N> {}

impl<const N: usize> fmt::Debug for Tag<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag<{}>({})", N, self.to_hex())
    }
}

impl<const N: usize> fmt::Display for Tag<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl<const N: usize> ConstantTimeEq for Tag<N> {
    fn ct_eq(&self, other: &Self) -> bool {
        dcrypt_core::util::constant_time::ct_eq(&self.data, &other.data)
    }
}

impl<const N: usize> RandomGeneration for Tag<N> {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut data = [0u8; N];
        rng.fill_bytes(&mut data);
        Ok(Self { data })
    }
}

impl<const N: usize> SecureZeroingType for Tag<N> {
    fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }
}

impl<const N: usize> FixedSize for Tag<N> {
    fn size() -> usize {
        N
    }
}

impl<const N: usize> ByteSerializable for Tag<N> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }
}

// Common tag size type aliases
pub type Tag16 = Tag<16>; // Common AEAD tag size
pub type Tag12 = Tag<12>; // Some AEAD modes use 12-byte tags
pub type Tag32 = Tag<32>; // Extended tag size for high security