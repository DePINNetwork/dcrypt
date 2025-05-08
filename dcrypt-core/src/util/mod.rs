//! Utility functions for the DCRYPT library

pub mod constant_time;
pub mod endian;
pub mod zeroing;
pub mod error_helpers;

pub use constant_time::*;
pub use endian::*;
pub use zeroing::*;
pub use error_helpers::*;

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