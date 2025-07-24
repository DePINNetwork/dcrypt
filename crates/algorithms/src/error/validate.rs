//! Validation utilities for cryptographic primitives

use super::{Error, Result};

/// Validate a parameter condition
#[inline(always)]
pub fn parameter(condition: bool, name: &'static str, reason: &'static str) -> Result<()> {
    if !condition {
        return Err(Error::param(name, reason));
    }
    Ok(())
}

/// Validate a length
#[inline(always)]
pub fn length(context: &'static str, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        return Err(Error::Length {
            context,
            expected,
            actual,
        });
    }
    Ok(())
}

/// Validate a minimum length
#[inline(always)]
pub fn min_length(context: &'static str, actual: usize, min: usize) -> Result<()> {
    if actual < min {
        return Err(Error::Length {
            context,
            expected: min,
            actual,
        });
    }
    Ok(())
}

/// Validate a maximum length
#[inline(always)]
pub fn max_length(context: &'static str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        return Err(Error::Length {
            context,
            expected: max,
            actual,
        });
    }
    Ok(())
}

/// Validate authentication
#[inline(always)]
pub fn authentication(is_valid: bool, algorithm: &'static str) -> Result<()> {
    if !is_valid {
        return Err(Error::Authentication { algorithm });
    }
    Ok(())
}
