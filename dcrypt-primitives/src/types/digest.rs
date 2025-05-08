//! Type-safe digest implementation with size guarantees
//!
//! Provides the `Digest` type, representing the output of a
//! cryptographic hash function with compile-time size guarantees.

use core::fmt;
use core::ops::{Deref, DerefMut};
use zeroize::Zeroize;
use hex;

use dcrypt_core::error::{DcryptError, Result};
use dcrypt_core::types::SecretBytes;
use crate::types::{ConstantTimeEq, SecureZeroingType, FixedSize, ByteSerializable};

/// A cryptographic digest with a fixed size
#[derive(Clone, Zeroize)]
pub struct Digest<const N: usize> {
    data: [u8; N],
    len: usize, // Actual length of valid data (for variable-length algorithms)
}

impl<const N: usize> Digest<N> {
    /// Create a new digest from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self { data, len: N }
    }
    
    /// Create a new digest with a specified logical length
    /// This is particularly useful for hash functions with variable output size
    pub fn with_len(data: [u8; N], len: usize) -> Self {
        if len > N {
            panic!("Logical length {} cannot exceed buffer size {}", len, N);
        }
        Self { data, len }
    }
    
    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(DcryptError::InvalidLength {
                context: "Digest::from_slice",
                expected: N,
                actual: slice.len(),
            });
        }
        
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        
        Ok(Self { data, len: N })
    }
    
    /// Get the length of the digest
    pub fn len(&self) -> usize {
        self.len
    }
    
    /// Check if the digest is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    
    /// Convert to a hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.data[..self.len])
    }
    
    /// Create from a hexadecimal string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        if hex_str.len() != N * 2 {
            return Err(DcryptError::InvalidLength {
                context: "Digest::from_hex",
                expected: N * 2,
                actual: hex_str.len(),
            });
        }
        
        let bytes = hex::decode(hex_str).map_err(|_| {
            DcryptError::InvalidParameter {
                context: "Digest::from_hex",
                #[cfg(feature = "std")]
                message: "Invalid hexadecimal string".to_string(),
            }
        })?;
        
        Self::from_slice(&bytes)
    }
}

impl<const N: usize> AsRef<[u8]> for Digest<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl<const N: usize> AsMut<[u8]> for Digest<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl<const N: usize> Deref for Digest<N> {
    type Target = [u8; N];
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for Digest<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> PartialEq for Digest<N> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.data[..self.len] == other.data[..other.len]
    }
}

impl<const N: usize> Eq for Digest<N> {}

impl<const N: usize> fmt::Debug for Digest<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest<{}>({}) [len={}]", N, self.to_hex(), self.len)
    }
}

impl<const N: usize> fmt::Display for Digest<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl<const N: usize> ConstantTimeEq for Digest<N> {
    fn ct_eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        dcrypt_core::util::constant_time::ct_eq(&self.data[..self.len], &other.data[..other.len])
    }
}

impl<const N: usize> SecureZeroingType for Digest<N> {
    fn zeroed() -> Self {
        Self { data: [0u8; N], len: N }
    }
}

impl<const N: usize> FixedSize for Digest<N> {
    fn size() -> usize {
        N
    }
}

impl<const N: usize> ByteSerializable for Digest<N> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data[..self.len].to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }
}

// Common digest size type aliases
pub type Digest20 = Digest<20>; // SHA-1
pub type Digest32 = Digest<32>; // SHA-256
pub type Digest48 = Digest<48>; // SHA-384
pub type Digest64 = Digest<64>; // SHA-512