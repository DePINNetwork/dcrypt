//! Block cipher modes of operation
//!
//! This module implements various modes of operation for block ciphers,
//! including CBC, CTR, and GCM.

pub mod cbc;
pub mod ctr;

// Re-exports
pub use cbc::Cbc;
pub use ctr::Ctr;