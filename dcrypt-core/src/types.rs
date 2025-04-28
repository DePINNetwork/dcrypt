//! Common types used across the DCRYPT library

use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::traits::serialize::Serialize;
use crate::error::Result;

/// Base key type that provides secure memory handling
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key(pub Vec<u8>);

impl Key {
    /// Create a new key from a byte array
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    
    /// Create a new key with zeros, of the given length
    pub fn new_zeros(len: usize) -> Self {
        Self(vec![0u8; len])
    }
    
    /// Get the length of the key
    pub fn len(&self) -> usize {
        self.0.len()
    }
    
    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Serialize for Key {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}

/// Wrapper for public key data
#[derive(Clone)]
pub struct PublicKey(pub Vec<u8>);

impl Zeroize for PublicKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Serialize for PublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}

/// Wrapper for ciphertext data
#[derive(Clone)]
pub struct Ciphertext(pub Vec<u8>);

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Ciphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Serialize for Ciphertext {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}
