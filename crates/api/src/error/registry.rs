//! Error registry for secure error handling

use core::sync::atomic::{AtomicPtr, Ordering};
use core::ptr::null_mut;

/// Global error registry for recording errors during constant-time operations
pub static ERROR_REGISTRY: ErrorRegistry = ErrorRegistry::new();

/// Thread-local registry for errors during constant-time operations
pub struct ErrorRegistry {
    error: AtomicPtr<()>,
}

impl ErrorRegistry {
    /// Create a new, empty error registry
    pub const fn new() -> Self {
        Self {
            error: AtomicPtr::new(null_mut()),
        }
    }
    
    /// Store an error in the registry
    pub fn store<E>(&self, error: E) {
        // For simplicity, we use std allocation since that's the default feature
        #[cfg(feature = "std")]
        {
            use std::boxed::Box;
            // Store the error as a trait object
            let boxed = Box::into_raw(Box::new(error));
            let old = self.error.swap(boxed as *mut (), Ordering::SeqCst);
            
            // Clean up any old error to avoid memory leaks
            if !old.is_null() {
                unsafe {
                    drop(Box::from_raw(old));
                }
            }
        }
        
        // In no-std environments, we can't store the error
        #[cfg(not(feature = "std"))]
        {
            let _ = error; // Avoid unused variable warning
            // Simply set a non-null pointer to indicate an error occurred
            self.error.store(1 as *mut (), Ordering::SeqCst);
        }
    }
    
    /// Clear any stored error
    pub fn clear(&self) {
        #[cfg(feature = "std")]
        {
            let ptr = self.error.swap(null_mut(), Ordering::SeqCst);
            if !ptr.is_null() {
                unsafe {
                    drop(Box::from_raw(ptr));
                }
            }
        }
        
        #[cfg(not(feature = "std"))]
        {
            self.error.store(null_mut(), Ordering::SeqCst);
        }
    }
    
    /// Check if an error is present
    pub fn has_error(&self) -> bool {
        !self.error.load(Ordering::SeqCst).is_null()
    }
    
    /// Get a copy of the last error, if any
    #[cfg(feature = "std")]
    pub fn get_error<E: Clone>(&self) -> Option<E> {
        let ptr = self.error.load(Ordering::SeqCst);
        if ptr.is_null() {
            None
        } else {
            // Safety: We know the type of the stored error when we retrieve it
            // The caller must ensure they request the correct type
            unsafe {
                let error_ref = &*(ptr as *const E);
                Some(error_ref.clone())
            }
        }
    }
}

impl Default for ErrorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ErrorRegistry {
    fn drop(&mut self) {
        self.clear();
    }
}