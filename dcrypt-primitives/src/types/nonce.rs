//! Type-safe nonce implementation with concrete sizes
//!
//! This module provides different nonce types with fixed sizes for various
//! cryptographic algorithms, ensuring proper type safety and validation.

use rand::{CryptoRng, RngCore};
use core::fmt;
use core::ops::{Deref, DerefMut};
use zeroize::Zeroize;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

/// Base trait for all nonce types
pub trait Nonce: AsRef<[u8]> + AsMut<[u8]> + Clone + Zeroize {
    /// Get the size of this nonce type in bytes
    fn size() -> usize where Self: Sized;
    
    /// Create a new nonce from a slice, validating the length
    fn from_slice(slice: &[u8]) -> Result<Self> where Self: Sized;
    
    /// Generate a random nonce
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> where Self: Sized;
    
    /// Check if two nonces are equal in constant time
    fn ct_eq(&self, other: &Self) -> bool;
}

/// 12-byte nonce (for ChaCha20-Poly1305, AES-GCM)
#[derive(Clone, Zeroize)]
pub struct Nonce12([u8; 12]);

impl Nonce12 {
    /// Create a new nonce from an existing array
    pub fn new(data: [u8; 12]) -> Self {
        Self(data)
    }
    
    /// Create a zeroed nonce
    pub fn zeroed() -> Self {
        Self([0u8; 12])
    }
}

impl Nonce for Nonce12 {
    fn size() -> usize {
        12
    }
    
    fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 12 {
            return Err(Error::InvalidLength {
                context: "Nonce12",
                needed: 12,
                got: slice.len(),
            });
        }
        
        let mut data = [0u8; 12];
        data.copy_from_slice(slice);
        
        Ok(Self(data))
    }
    
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut data = [0u8; 12];
        rng.fill_bytes(&mut data);
        Ok(Self(data))
    }
    
    fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl AsRef<[u8]> for Nonce12 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Nonce12 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for Nonce12 {
    type Target = [u8; 12];
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Nonce12 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for Nonce12 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for Nonce12 {}

impl fmt::Debug for Nonce12 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce12({:?})", &self.0[..])
    }
}

/// 16-byte nonce (for AES-CTR, other modes)
#[derive(Clone, Zeroize)]
pub struct Nonce16([u8; 16]);

impl Nonce16 {
    /// Create a new nonce from an existing array
    pub fn new(data: [u8; 16]) -> Self {
        Self(data)
    }
    
    /// Create a zeroed nonce
    pub fn zeroed() -> Self {
        Self([0u8; 16])
    }
}

impl Nonce for Nonce16 {
    fn size() -> usize {
        16
    }
    
    fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 16 {
            return Err(Error::InvalidLength {
                context: "Nonce16",
                needed: 16,
                got: slice.len(),
            });
        }
        
        let mut data = [0u8; 16];
        data.copy_from_slice(slice);
        
        Ok(Self(data))
    }
    
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut data = [0u8; 16];
        rng.fill_bytes(&mut data);
        Ok(Self(data))
    }
    
    fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl AsRef<[u8]> for Nonce16 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Nonce16 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for Nonce16 {
    type Target = [u8; 16];
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Nonce16 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for Nonce16 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for Nonce16 {}

impl fmt::Debug for Nonce16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce16({:?})", &self.0[..])
    }
}

/// 24-byte nonce (for XChaCha20-Poly1305)
#[derive(Clone, Zeroize)]
pub struct Nonce24([u8; 24]);

impl Nonce24 {
    /// Create a new nonce from an existing array
    pub fn new(data: [u8; 24]) -> Self {
        Self(data)
    }
    
    /// Create a zeroed nonce
    pub fn zeroed() -> Self {
        Self([0u8; 24])
    }
}

impl Nonce for Nonce24 {
    fn size() -> usize {
        24
    }
    
    fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 24 {
            return Err(Error::InvalidLength {
                context: "Nonce24",
                needed: 24,
                got: slice.len(),
            });
        }
        
        let mut data = [0u8; 24];
        data.copy_from_slice(slice);
        
        Ok(Self(data))
    }
    
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut data = [0u8; 24];
        rng.fill_bytes(&mut data);
        Ok(Self(data))
    }
    
    fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl AsRef<[u8]> for Nonce24 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Nonce24 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for Nonce24 {
    type Target = [u8; 24];
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Nonce24 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for Nonce24 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for Nonce24 {}

impl fmt::Debug for Nonce24 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce24({:?})", &self.0[..])
    }
}

// Common functions

/// Generate a nonce of appropriate size for a given algorithm
pub fn generate_nonce<R: RngCore + CryptoRng, T: Nonce>(rng: &mut R) -> Result<T> {
    T::generate(rng)
}