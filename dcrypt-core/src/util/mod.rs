//! Utility functions for the DCRYPT library

pub mod constant_time;
pub mod endian;
pub mod zeroing;
#[deprecated(since = "0.2.0", note = "Use crate::error::validate instead")]
pub mod error_helpers;

pub use constant_time::*;
pub use endian::*;
pub use zeroing::*;
#[deprecated(since = "0.2.0", note = "Use crate::error::validate instead")]
pub use error_helpers::*;

// Re-export the new error validation module for convenience
pub use crate::error::validate as validate_new;

#[cfg(feature = "simd")]
pub mod simd {
    //! SIMD utility functions

    /// Check if SIMD is available
    pub fn is_available() -> bool {
        #[cfg(target_feature = "sse2")]
        {
            return true;
        }

        #[cfg(not(target_feature = "sse2"))]
        {
            return false;
        }
    }
}