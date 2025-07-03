//! Secret data types with guaranteed zeroization
//!
//! This module provides type-safe wrappers for sensitive data that ensure
//! proper cleanup and zeroization when the data is no longer needed.

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::convert::{AsRef, AsMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Handle Vec import based on features
#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

/// Trait for types that can be securely zeroed and cloned
pub trait SecureZeroingType: Zeroize + Clone {
    /// Create a zeroed instance
    fn zeroed() -> Self;
    
    /// Create a secure clone that preserves security properties
    ///
    /// This method ensures that cloned instances maintain the same
    /// security guarantees as the original, including proper zeroization.
    fn secure_clone(&self) -> Self {
        self.clone()  // Default implementation uses regular clone
    }
}

/// Fixed-size secret buffer that guarantees zeroization
///
/// This type provides:
/// - Automatic zeroization on drop
/// - Secure cloning that preserves security properties
/// - Type-safe size guarantees at compile time
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecretBuffer<N> {
    /// Create a new secret buffer with the given data
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }
    
    /// Create a zeroed secret buffer
    pub fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }
    
    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        N
    }
    
    /// Check if the buffer is empty (always false for non-zero N)
    pub fn is_empty(&self) -> bool {
        N == 0
    }
    
    /// Get a reference to the inner data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    /// Get a mutable reference to the inner data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> SecureZeroingType for SecretBuffer<N> {
    fn zeroed() -> Self {
        Self::zeroed()
    }
    
    fn secure_clone(&self) -> Self {
        Self::new(self.data)  // Fixed: removed .clone() since [u8; N] implements Copy
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBuffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for SecretBuffer<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> fmt::Debug for SecretBuffer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuffer<{}>([REDACTED])", N)
    }
}

/// Variable-size secret vector that guarantees zeroization
///
/// This type provides:
/// - Automatic zeroization on drop
/// - Secure cloning that preserves security properties
/// - Dynamic sizing with secure memory management
#[cfg(feature = "alloc")]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    data: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl SecretVec {
    /// Create a new secret vector with the given data
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    /// Create a secret vector from a slice
    pub fn from_slice(slice: &[u8]) -> Self {
        Self { data: slice.to_vec() }
    }
    
    /// Create an empty secret vector
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }
    
    /// Create a secret vector with the specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self { data: Vec::with_capacity(capacity) }
    }
    
    /// Get the length of the vector
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the vector is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Get a reference to the inner data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    /// Get a mutable reference to the inner data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    /// Extend the vector with additional data
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }
    
    /// Resize the vector to the specified length
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data.resize(new_len, value);
    }
    
    /// Truncate the vector to the specified length
    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }
}

#[cfg(feature = "alloc")]
impl SecureZeroingType for SecretVec {
    fn zeroed() -> Self {
        Self::empty()
    }
    
    fn secure_clone(&self) -> Self {
        Self::new(self.data.clone())
    }
}

#[cfg(feature = "alloc")]
impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(feature = "alloc")]
impl AsMut<[u8]> for SecretVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[cfg(feature = "alloc")]
impl From<Vec<u8>> for SecretVec {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

#[cfg(feature = "alloc")]
impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretVec(len={}, [REDACTED])", self.data.len())
    }
}

/// Ephemeral secret that is automatically zeroized after use
///
/// This type wraps any type T and ensures it is zeroized when dropped.
/// It's useful for temporary secrets and intermediate cryptographic values.
pub struct EphemeralSecret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> EphemeralSecret<T> {
    /// Create a new ephemeral secret
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }
    
    /// Consume the secret and return the inner value
    ///
    /// Note: After calling this method, the caller is responsible
    /// for ensuring the value is properly zeroized.
    pub fn into_inner(self) -> T {
        let this = core::mem::ManuallyDrop::new(self);
        unsafe {
            core::ptr::read(&this.inner)
        }
    }
}

// Fixed: Implement actual AsRef and AsMut traits instead of methods
impl<T: Zeroize> AsRef<T> for EphemeralSecret<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> AsMut<T> for EphemeralSecret<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Zeroize> Drop for EphemeralSecret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for EphemeralSecret<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

impl<T: Zeroize + Default> Default for EphemeralSecret<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Zeroize> Deref for EphemeralSecret<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for EphemeralSecret<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Zeroize + fmt::Debug> fmt::Debug for EphemeralSecret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EphemeralSecret([REDACTED])")
    }
}

/// Guard type that ensures a value is zeroized when dropped
///
/// This is useful for ensuring cleanup happens even in the presence
/// of early returns or panics.
pub struct ZeroizeGuard<'a, T: Zeroize> {
    value: &'a mut T,
}

impl<'a, T: Zeroize> ZeroizeGuard<'a, T> {
    /// Create a new zeroize guard for the given value
    pub fn new(value: &'a mut T) -> Self {
        Self { value }
    }
}

// Fixed: Use lifetime elision instead of explicit lifetimes
impl<T: Zeroize> Drop for ZeroizeGuard<'_, T> {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl<T: Zeroize> Deref for ZeroizeGuard<'_, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        self.value
    }
}

impl<T: Zeroize> DerefMut for ZeroizeGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secret_buffer_basic() {
        let mut buffer = SecretBuffer::<32>::new([42u8; 32]);
        assert_eq!(buffer.len(), 32);
        assert_eq!(buffer.as_slice()[0], 42);
        
        // Test mutation
        buffer.as_mut_slice()[0] = 1;
        assert_eq!(buffer.as_slice()[0], 1);
    }
    
    #[test]
    fn test_secret_buffer_secure_clone() {
        let buffer = SecretBuffer::<16>::new([0xAA; 16]);
        let cloned = buffer.secure_clone();
        assert_eq!(cloned.as_slice(), buffer.as_slice());
    }
    
    #[test]
    fn test_secret_buffer_zeroed() {
        let zeroed = SecretBuffer::<32>::zeroed();
        assert_eq!(zeroed.as_slice(), &[0u8; 32]);
    }
    
    #[cfg(feature = "alloc")]
    #[test]
    fn test_secret_vec_operations() {
        let mut vec = SecretVec::from_slice(&[1, 2, 3, 4]);
        assert_eq!(vec.len(), 4);
        assert_eq!(vec.as_slice(), &[1, 2, 3, 4]);
        
        // Test extend
        vec.extend_from_slice(&[5, 6]);
        assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5, 6]);
        
        // Test truncate
        vec.truncate(3);
        assert_eq!(vec.as_slice(), &[1, 2, 3]);
        
        // Test resize
        vec.resize(5, 0xFF);
        assert_eq!(vec.as_slice(), &[1, 2, 3, 0xFF, 0xFF]);
    }
    
    #[test]
    fn test_ephemeral_secret() {
        #[derive(Clone, Zeroize)]
        struct TestSecret(u64);
        
        let secret = EphemeralSecret::new(TestSecret(42));
        assert_eq!(secret.0, 42);
        
        // Test deref
        let value = secret.0;
        assert_eq!(value, 42);
        
        // Test clone
        let cloned = secret.clone();
        assert_eq!(cloned.0, 42);
        
        // Test into_inner
        let inner = secret.into_inner();
        assert_eq!(inner.0, 42);
    }
    
    #[test]
    fn test_zeroize_guard() {
        let mut value = vec![1u8, 2, 3, 4];
        {
            let guard = ZeroizeGuard::new(&mut value);
            // Simulate work with the value
            assert_eq!(&**guard, &[1, 2, 3, 4]);
        }
        // Guard should have zeroized the value (which clears the Vec)
        assert!(value.is_empty());
    }
}