//! Error handling helper functions for dcrypt-core
//! 
//! Note: This module is deprecated and will be removed in a future version.
//! Please use the functionality in crate::error::validate instead.

use crate::error::{Error, Result};

#[cfg(feature = "std")]
use std::string::String;

/// Validate the length of a byte slice against minimum and optional maximum bounds
///
/// # Arguments
///
/// * `data` - The byte slice to validate
/// * `min_len` - The minimum required length
/// * `max_len` - The optional maximum allowed length
/// * `context` - A description of what is being validated
///
/// # Returns
///
/// `Ok(())` if the length is valid, or an `Error::InvalidLength` otherwise
#[deprecated(since = "0.2.0", note = "Use crate::error::validate::length instead")]
pub fn validate_length(
    data: &[u8],
    min_len: usize,
    max_len: Option<usize>,
    context: &'static str
) -> Result<()> {
    if data.len() < min_len {
        return Err(Error::InvalidLength {
            context,
            expected: min_len,
            actual: data.len(),
        });
    }
    
    if let Some(max) = max_len {
        if data.len() > max {
            return Err(Error::InvalidLength {
                context,
                expected: max,
                actual: data.len(),
            });
        }
    }
    
    Ok(())
}

/// Validate that a value equals the expected value, returning an error if not
///
/// # Arguments
///
/// * `actual` - The actual value
/// * `expected` - The expected value
/// * `context` - A description of what is being validated
///
/// # Returns
///
/// `Ok(())` if the values match, or an `Error::InvalidParameter` otherwise
#[cfg(feature = "std")]
#[deprecated(since = "0.2.0", note = "Use crate::error::validate::check_parameter instead")]
pub fn validate_eq<T: PartialEq>(
    actual: T,
    expected: T,
    context: &'static str
) -> Result<()>
where
    T: core::fmt::Debug,
{
    if actual != expected {
        return Err(Error::InvalidParameter {
            context,
            message: format!("Expected {:?}, got {:?}", expected, actual),
        });
    }
    
    Ok(())
}

/// No-std version of validate_eq
#[cfg(not(feature = "std"))]
#[deprecated(since = "0.2.0", note = "Use crate::error::validate::check_parameter instead")]
pub fn validate_eq<T: PartialEq>(
    actual: T,
    expected: T,
    context: &'static str
) -> Result<()> {
    if actual != expected {
        return Err(Error::InvalidParameter {
            context,
        });
    }
    
    Ok(())
}

/// Validate that a value is within a range, returning an error if not
///
/// # Arguments
///
/// * `value` - The value to validate
/// * `min` - The minimum allowed value (inclusive)
/// * `max` - The maximum allowed value (inclusive)
/// * `context` - A description of what is being validated
///
/// # Returns
///
/// `Ok(())` if the value is within range, or an `Error::InvalidParameter` otherwise
#[cfg(feature = "std")]
#[deprecated(since = "0.2.0", note = "Use crate::error::validate::range_length instead")]
pub fn validate_range<T: PartialOrd>(
    value: T,
    min: T,
    max: T,
    context: &'static str
) -> Result<()>
where
    T: core::fmt::Debug,
{
    if value < min || value > max {
        return Err(Error::InvalidParameter {
            context,
            message: format!("Value {:?} outside range [{:?}, {:?}]", value, min, max),
        });
    }
    
    Ok(())
}

/// No-std version of validate_range
#[cfg(not(feature = "std"))]
#[deprecated(since = "0.2.0", note = "Use crate::error::validate::range_length instead")]
pub fn validate_range<T: PartialOrd>(
    value: T,
    min: T,
    max: T,
    context: &'static str
) -> Result<()> {
    if value < min || value > max {
        return Err(Error::InvalidParameter {
            context,
        });
    }
    
    Ok(())
}

/// Add context to any Result<T, E> that can be converted to Error
///
/// # Arguments
///
/// * `result` - The result to add context to
/// * `context` - The context description
///
/// # Returns
///
/// The original result with updated context if it was an error
#[deprecated(since = "0.2.0", note = "Use crate::error::traits::ResultExt::with_context instead")]
pub fn with_context<T, E: Into<Error>>(
    result: core::result::Result<T, E>,
    context: &'static str
) -> Result<T> {
    result.map_err(|e| {
        let error = e.into();
        error.with_context(context)
    })
}

/// Ensure that a condition is true, returning an InvalidParameter error if not
///
/// # Arguments
///
/// * `condition` - The condition to check
/// * `context` - A description of what is being validated
/// * `message` - A message describing the expected condition
///
/// # Returns
///
/// `Ok(())` if the condition is true, or an `Error::InvalidParameter` otherwise
#[cfg(feature = "std")]
#[deprecated(since = "0.2.0", note = "Use crate::error::validate::check_parameter instead")]
pub fn ensure(
    condition: bool, 
    context: &'static str,
    message: &str
) -> Result<()> {
    if !condition {
        return Err(Error::InvalidParameter {
            context,
            message: message.to_string(),
        });
    }
    
    Ok(())
}

/// No-std version of ensure
#[cfg(not(feature = "std"))]
#[deprecated(since = "0.2.0", note = "Use crate::error::validate::check_parameter instead")]
pub fn ensure(
    condition: bool, 
    context: &'static str,
) -> Result<()> {
    if !condition {
        return Err(Error::InvalidParameter {
            context,
        });
    }
    
    Ok(())
}

/// Create a not implemented error
///
/// # Arguments
///
/// * `feature` - The feature that is not implemented
///
/// # Returns
///
/// A `Error::NotImplemented` error
#[deprecated(since = "0.2.0", note = "Use crate::error::validate::not_implemented instead")]
pub fn not_implemented(feature: &'static str) -> Error {
    Error::NotImplemented {
        feature,
    }
}