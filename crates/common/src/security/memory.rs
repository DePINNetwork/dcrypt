//! Memory safety patterns and secure operations
//!
//! This module provides traits and utilities for ensuring memory safety
//! in cryptographic operations.

use api::Result;

// Handle Vec and Box imports based on features
#[cfg(feature = "std")]
use std::{vec::Vec, boxed::Box};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{vec::Vec, boxed::Box};

/// Type alias for cleanup functions used in secure operations
#[cfg(any(feature = "std", feature = "alloc"))]
pub type CleanupFn<T> = Box<dyn FnOnce(&mut T)>;

/// Trait for secure cryptographic operations
///
/// This trait ensures that sensitive data is properly handled and cleared
/// after operations complete, whether they succeed or fail.
pub trait SecureOperation<T> {
    /// Execute the operation securely
    ///
    /// This method should:
    /// 1. Perform the cryptographic operation
    /// 2. Clear all sensitive intermediate data
    /// 3. Return the result or error
    fn execute_secure(self) -> Result<T>;
    
    /// Clear all sensitive data associated with this operation
    ///
    /// This method is called automatically by `execute_secure` but can
    /// also be called manually when needed.
    fn clear_sensitive_data(&mut self);
}

/// Extension trait for operations that produce a result
pub trait SecureOperationExt: Sized {
    type Output;
    
    /// Execute the operation and ensure cleanup on both success and failure
    fn execute_with_cleanup<F>(self, cleanup: F) -> Result<Self::Output>
    where
        F: FnOnce();
}

/// Builder pattern for secure operations
///
/// This pattern allows for composing operations while maintaining
/// security guarantees at each step.
#[cfg(any(feature = "std", feature = "alloc"))]
pub struct SecureOperationBuilder<T> {
    state: T,
    cleanup_fns: Vec<CleanupFn<T>>,
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl<T> SecureOperationBuilder<T> {
    /// Create a new secure operation builder
    pub fn new(initial_state: T) -> Self {
        Self {
            state: initial_state,
            cleanup_fns: Vec::new(),
        }
    }
    
    /// Add a cleanup function to be called when the operation completes
    pub fn with_cleanup<F>(mut self, cleanup: F) -> Self
    where
        F: FnOnce(&mut T) + 'static,
    {
        self.cleanup_fns.push(Box::new(cleanup));
        self
    }
    
    /// Transform the state
    pub fn transform<U, F>(self, f: F) -> SecureOperationBuilder<U>
    where
        F: FnOnce(T) -> U,
    {
        SecureOperationBuilder {
            state: f(self.state),
            cleanup_fns: Vec::new(), // Cleanup functions don't transfer
        }
    }
    
    /// Build and execute the operation
    pub fn build<O, F>(self, operation: F) -> Result<O>
    where
        F: FnOnce(&mut T) -> Result<O>,
    {
        let mut state = self.state;
        let result = operation(&mut state);
        
        // Execute cleanup functions regardless of success/failure
        for cleanup in self.cleanup_fns.into_iter().rev() {
            cleanup(&mut state);
        }
        
        result
    }
}

/// Trait for types that can be securely compared
///
/// This trait provides constant-time comparison operations to prevent
/// timing attacks.
pub trait SecureCompare: Sized {
    /// Compare two values in constant time
    fn secure_eq(&self, other: &Self) -> bool;
    
    /// Compare two values and return a constant-time choice
    fn secure_cmp(&self, other: &Self) -> subtle::Choice;
}

impl<const N: usize> SecureCompare for [u8; N] {
    fn secure_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.ct_eq(other))
    }
    
    fn secure_cmp(&self, other: &Self) -> subtle::Choice {
        use subtle::ConstantTimeEq;
        self.ct_eq(other)
    }
}

impl SecureCompare for &[u8] {
    fn secure_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.ct_eq(other))
    }
    
    fn secure_cmp(&self, other: &Self) -> subtle::Choice {
        use subtle::ConstantTimeEq;
        self.ct_eq(other)
    }
}

/// Memory barrier utilities
pub mod barrier {
    use core::sync::atomic::{compiler_fence, fence, Ordering};
    
    /// Insert a compiler fence to prevent reordering
    #[inline(always)]
    pub fn compiler_fence_seq_cst() {
        compiler_fence(Ordering::SeqCst);
    }
    
    /// Insert a full memory fence
    #[inline(always)]
    pub fn memory_fence_seq_cst() {
        fence(Ordering::SeqCst);
    }
    
    /// Execute a closure with memory barriers before and after
    #[inline(always)]
    pub fn with_barriers<T, F: FnOnce() -> T>(f: F) -> T {
        compiler_fence_seq_cst();
        let result = f();
        compiler_fence_seq_cst();
        result
    }
}

/// Secure allocation utilities
#[cfg(feature = "alloc")]
pub mod alloc {
    use super::*;
    use zeroize::Zeroize;
    
    /// Allocate memory for sensitive data with appropriate protections
    ///
    /// Note: This is a placeholder for platform-specific secure allocation.
    /// In a real implementation, this might use mlock() on Unix systems
    /// or VirtualLock() on Windows.
    pub fn secure_alloc<T: Default + Zeroize + Clone>(size: usize) -> Result<Vec<T>> {
        // For now, just use regular allocation
        // TODO: Implement platform-specific secure allocation
        Ok(vec![T::default(); size])
    }
    
    /// Free memory and ensure it's zeroized
    pub fn secure_free<T: Zeroize>(mut data: Vec<T>) {
        // Zeroize the data
        for item in data.iter_mut() {
            item.zeroize();
        }
        // Let the vector be dropped normally
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;
    
    #[cfg(any(feature = "std", feature = "alloc"))]
    struct TestOperation {
        secret: Vec<u8>,
        result: Option<Vec<u8>>,
    }
    
    #[cfg(any(feature = "std", feature = "alloc"))]
    impl SecureOperation<Vec<u8>> for TestOperation {
        fn execute_secure(mut self) -> Result<Vec<u8>> {
            // Simulate some operation
            self.result = Some(self.secret.iter().map(|&b| b ^ 0xFF).collect());
            let result = self.result.clone().unwrap();
            self.clear_sensitive_data();
            Ok(result)
        }
        
        fn clear_sensitive_data(&mut self) {
            self.secret.zeroize();
            if let Some(ref mut result) = self.result {
                result.zeroize();
            }
            self.result = None;
        }
    }
    
    #[test]
    #[cfg(any(feature = "std", feature = "alloc"))]
    fn test_secure_operation() {
        let op = TestOperation {
            secret: vec![1, 2, 3, 4],
            result: None,
        };
        
        let result = op.execute_secure().unwrap();
        assert_eq!(result, vec![254, 253, 252, 251]);
    }
    
    #[test]
    fn test_secure_compare() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        
        assert!(a.secure_eq(&b));
        assert!(!a.secure_eq(&c));
    }
    
    #[test]
    fn test_memory_barriers() {
        use barrier::*;
        
        let result = with_barriers(|| {
            let mut x = 42;
            x += 1;
            x
        });
        
        assert_eq!(result, 43);
    }
}