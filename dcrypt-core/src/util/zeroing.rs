//! Secure memory zeroing utilities

use zeroize::Zeroize;

/// Securely zero a slice of memory
///
/// This function ensures that the contents of the slice are securely
/// zeroed, even if the compiler would otherwise optimize the operation away.
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Securely clone a slice, zeroing the source afterwards
///
/// This function clones the contents of the slice and then securely
/// zeroes the original slice.
pub fn secure_clone_and_zero(data: &mut [u8]) -> Vec<u8> {
    let result = data.to_vec();
    secure_zero(data);
    result
}

/// Guard that zeroes memory when dropped
///
/// This struct provides a way to ensure that memory is zeroed when
/// it goes out of scope, by automatically zeroing the contained
/// buffer when the `ZeroGuard` is dropped.
pub struct ZeroGuard<'a>(&'a mut [u8]);

impl<'a> ZeroGuard<'a> {
    /// Create a new guard that will zero the given data when dropped
    pub fn new(data: &'a mut [u8]) -> Self {
        Self(data)
    }
    
    /// Get a reference to the protected data
    pub fn data(&self) -> &[u8] {
        self.0
    }
    
    /// Get a mutable reference to the protected data
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl<'a> Drop for ZeroGuard<'a> {
    fn drop(&mut self) {
        secure_zero(self.0);
    }
}
