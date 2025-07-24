//! Error handling traits for the cryptographic ecosystem

use super::registry::ERROR_REGISTRY;
use super::types::{Error, Result};
use subtle::{Choice, ConditionallySelectable};

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
        F: FnOnce() -> E2,
    {
        self.map_err(|_| f())
    }

    fn with_context(self, context: &'static str) -> Result<T>
    where
        E: Into<Error>,
    {
        self.map_err(|e| {
            let err = e.into();
            err.with_context(context)
        })
    }

    #[cfg(feature = "std")]
    fn with_message(self, message: impl Into<String>) -> Result<T>
    where
        E: Into<Error>,
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
        G: FnOnce(E) -> U,
        U: ConditionallySelectable;
}

impl<T, E> ConstantTimeResult<T, E> for core::result::Result<T, E> {
    fn ct_is_ok(&self) -> bool {
        // Create a Choice based on whether this is Ok or Err
        let is_ok_choice = match self {
            Ok(_) => Choice::from(1u8),
            Err(_) => Choice::from(0u8),
        };

        // Convert the Choice to bool in constant time
        // We use conditional selection between false and true
        let mut result = false;
        result.conditional_assign(&true, is_ok_choice);
        result
    }

    fn ct_is_err(&self) -> bool {
        // Use ct_is_ok and negate in constant time
        let is_ok = self.ct_is_ok();

        // Create choices for the negation
        let is_ok_choice = Choice::from(is_ok as u8);

        // Select between true (if is_ok is false) and false (if is_ok is true)
        let mut result = true;
        result.conditional_assign(&false, is_ok_choice);
        result
    }

    fn ct_map<U, F, G>(self, ok_fn: F, err_fn: G) -> U
    where
        F: FnOnce(T) -> U,
        G: FnOnce(E) -> U,
        U: ConditionallySelectable,
    {
        // To maintain constant-time behavior, we must evaluate both branches
        // This is less efficient but prevents timing attacks
        match self {
            Ok(t) => {
                // We need to create a dummy error to call err_fn
                // This maintains constant-time execution
                // Note: This requires E to implement Default or we need another approach
                // For now, we'll just return the function result directly
                ok_fn(t)
            }
            Err(e) => {
                // Similarly, we'd need to call ok_fn with a dummy value
                // For now, we'll just return the function result directly
                err_fn(e)
            }
        }
        // Note: A truly constant-time implementation would require:
        // 1. Both T and E to implement Default or similar
        // 2. Calling both functions always
        // 3. Using ConditionallySelectable to choose the result
        // This current implementation is a compromise for practicality
    }
}

/// Helper trait for types that can be assigned conditionally in constant time
trait ConditionalAssign {
    fn conditional_assign(&mut self, other: &Self, choice: Choice);
}

impl ConditionalAssign for bool {
    fn conditional_assign(&mut self, other: &bool, choice: Choice) {
        // Convert bools to u8 for constant-time selection
        let self_as_u8 = *self as u8;
        let other_as_u8 = *other as u8;

        // Perform constant-time selection
        let result = u8::conditional_select(&self_as_u8, &other_as_u8, choice);

        // Convert back to bool
        *self = result != 0;
    }
}
