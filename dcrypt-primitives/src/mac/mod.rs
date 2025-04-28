//! Message Authentication Code (MAC) implementations
//!
//! This module contains implementations of various MACs
//! used throughout the DCRYPT library.

pub mod poly1305;
pub use poly1305::{Poly1305, POLY1305_KEY_SIZE, POLY1305_TAG_SIZE};
