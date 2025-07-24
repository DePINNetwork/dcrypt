//! Core types with security guarantees for the DCRYPT library
//!
//! This module provides fundamental type definitions that enforce
//! compile-time and runtime guarantees for cryptographic operations.

use core::fmt;
use core::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::{Error, Result, Serialize};
use dcrypt_internal::constant_time::ct_eq;

/// A fixed-size array of bytes that is securely zeroed when dropped
///
/// This type provides:
/// - Compile-time size guarantees via const generics
/// - Secure zeroing when dropped
/// - Constant-time equality comparison
/// - Debug implementation that hides the actual bytes
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Create a new instance from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }
    
    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidLength {
                context: "SecretBytes::from_slice",
                expected: N,
                actual: slice.len(),
            });
        }
        
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        
        Ok(Self { data })
    }
    
    /// Create an instance filled with zeros
    pub fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }
    
    /// Generate a random instance
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut data = [0u8; N];
        rng.fill_bytes(&mut data);
        Self { data }
    }
    
    /// Get the length of the contained data
    pub fn len(&self) -> usize {
        N
    }
    
    /// Check if the container is empty
    pub fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for SecretBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Deref for SecretBytes<N> {
    type Target = [u8; N];
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for SecretBytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.data, other.data)
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{}>[REDACTED]", N)
    }
}

impl<const N: usize> Serialize for SecretBytes<N> {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.to_vec())
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }
}

/// A variable-length vector of bytes that is securely zeroed when dropped
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    data: Vec<u8>,
}

impl SecretVec {
    /// Create a new instance from an existing vector
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    /// Create by copying from a slice
    pub fn from_slice(slice: &[u8]) -> Self {
        Self { data: slice.to_vec() }
    }
    
    /// Create filled with zeros
    pub fn zeroed(len: usize) -> Self {
        Self { data: vec![0u8; len] }
    }
    
    /// Generate a random instance
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R, len: usize) -> Self {
        let mut data = vec![0u8; len];
        rng.fill_bytes(&mut data);
        Self { data }
    }
    
    /// Get the length of the contained data
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the container is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecretVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Deref for SecretVec {
    type Target = Vec<u8>;
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecretVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl PartialEq for SecretVec {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.data, &other.data)
    }
}

impl Eq for SecretVec {}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretVec({})[REDACTED]", self.data.len())
    }
}

impl Serialize for SecretVec {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::from_slice(bytes))
    }
}

/// Base key type that provides secure memory handling
/// 
/// Enhanced version of the original Key type with additional security features
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key {
    data: Vec<u8>,
}

impl Key {
    /// Create a new key from a byte array
    pub fn new(bytes: &[u8]) -> Self {
        Self { data: bytes.to_vec() }
    }
    
    /// Create a new key with zeros
    pub fn new_zeros(len: usize) -> Self {
        Self { data: vec![0u8; len] }
    }
    
    /// Get the length of the key
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for Key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Serialize for Key {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::new(bytes))
    }
}

/// Wrapper for public key data
#[derive(Clone)]
pub struct PublicKey {
    data: Vec<u8>,
}

impl PublicKey {
    /// Create a new public key from a byte array
    pub fn new(bytes: &[u8]) -> Self {
        Self { data: bytes.to_vec() }
    }
    
    /// Get the length of the key
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Zeroize for PublicKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Serialize for PublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::new(bytes))
    }
}

/// Wrapper for ciphertext data
#[derive(Clone)]
pub struct Ciphertext {
    data: Vec<u8>,
}

impl Ciphertext {
    /// Create a new ciphertext from a byte array
    pub fn new(bytes: &[u8]) -> Self {
        Self { data: bytes.to_vec() }
    }
    
    /// Get the length of the ciphertext
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the ciphertext is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for Ciphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Serialize for Ciphertext {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::new(bytes))
    }
}