//! Security primitives and memory safety utilities
//!
//! This module provides foundational security types and patterns used throughout
//! the dcrypt ecosystem to ensure proper handling of sensitive cryptographic material.

pub mod memory;
pub mod secret;

// Re-export core security types
pub use secret::{EphemeralSecret, SecretBuffer, SecureZeroingType, ZeroizeGuard};

// Conditionally re-export SecretVec only when alloc feature is enabled
#[cfg(feature = "alloc")]
pub use secret::SecretVec;

// Re-export memory safety traits and utilities
pub use memory::{SecureCompare, SecureOperation, SecureOperationExt};

// Conditionally re-export SecureOperationBuilder only when std or alloc features are enabled
#[cfg(any(feature = "std", feature = "alloc"))]
pub use memory::SecureOperationBuilder;

// Re-export memory barrier utilities
pub use memory::barrier;
