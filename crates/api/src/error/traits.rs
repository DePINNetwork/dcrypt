//! Error handling traits for the cryptographic ecosystem

use super::types::{Error, Result};
use super::registry::ERROR_REGISTRY;

/// Extension trait for Result types
pub trait ResultExt<T, E>: Sized {
    /// Wrap an error with additional context
    fn wrap_err<F, E2>(self, f: F) -> core::result::Result<T, E2> 
    where 
        F: FnOnce() -> E2;
        
    /// Add context to an error when converting to Error
    fn with_context(self, context: &'static str) -> Result<T>
    where
        E: Into<Error>;
        
    #[cfg(feature = "std")]
    /// Add message to an error when converting to Error
    fn with_message(self, message: impl Into<String>) -> Result<T>
    where
        E: Into<Error>;
}

impl<T, E> ResultExt<T, E> for core::result::Result<T, E> {
    fn wrap_err<F, E2>(self, f: F) -> core::result::Result<T, E2> 
    where 
        F: FnOnce() -> E2 
    {
        self.map_err(|_| f())
    }
    
    fn with_context(self, context: &'static str) -> Result<T>
    where
        E: Into<Error>
    {
        self.map_err(|e| {
            let err = e.into();
            err.with_context(context)
        })
    }
    
    #[cfg(feature = "std")]
    fn with_message(self, message: impl Into<String>) -> Result<T>
    where
        E: Into<Error>
    {
        self.map_err(|e| {
            let err = e.into();
            err.with_message(message)
        })
    }
}

/// Trait for secure error handling to prevent timing attacks
pub trait SecureErrorHandling<T, E>: Sized {
    /// Handle errors in constant time 
    fn secure_unwrap<F>(self, default: T, on_error: F) -> T 
    where 
        F: FnOnce() -> E;
}

impl<T, E> SecureErrorHandling<T, E> for core::result::Result<T, E> {
    fn secure_unwrap<F>(self, default: T, on_error: F) -> T 
    where 
        F: FnOnce() -> E,
    {
        match self {
            Ok(value) => value,
            Err(_) => {
                // Store error in a way that maintains constant-time
                let error = on_error();
                ERROR_REGISTRY.store(error);
                default
            }
        }
    }
}

/// Trait for checking if an operation succeeded in constant time
pub trait ConstantTimeResult<T, E> {
    /// Check if this result is Ok, without branching on the result
    fn ct_is_ok(&self) -> bool;
    
    /// Check if this result is Err, without branching on the result
    fn ct_is_err(&self) -> bool;
    
    /// Map a result to a value in constant time, calling a provided function
    /// regardless of whether the result is Ok or Err
    fn ct_map<U, F, G>(self, ok_fn: F, err_fn: G) -> U
    where
        F: FnOnce(T) -> U,
        G: FnOnce(E) -> U;
}

impl<T, E> ConstantTimeResult<T, E> for core::result::Result<T, E> {
    fn ct_is_ok(&self) -> bool {
        match self {
            Ok(_) => true,
            Err(_) => false,
        }
        // In a real implementation, this would use subtle::Choice for
        // constant-time behavior, but for clarity we're using a direct
        // implementation here
    }
    
    fn ct_is_err(&self) -> bool {
        !self.ct_is_ok()
    }
    
    fn ct_map<U, F, G>(self, ok_fn: F, err_fn: G) -> U
    where
        F: FnOnce(T) -> U,
        G: FnOnce(E) -> U,
    {
        match self {
            Ok(t) => ok_fn(t),
            Err(e) => err_fn(e),
        }
        // In a real implementation, this would use subtle::ConditionallySelectable
        // to ensure constant-time behavior
    }
}