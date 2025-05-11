//! Security primitives and memory safety utilities
//!
//! This module provides foundational security types and patterns used throughout
//! the dcrypt ecosystem to ensure proper handling of sensitive cryptographic material.

pub mod secret;
pub mod memory;

// Re-export core security types
pub use secret::{
    SecretBuffer, 
    EphemeralSecret, 
    ZeroizeGuard,
    SecureZeroingType,
};

// Conditionally re-export SecretVec only when alloc feature is enabled
#[cfg(feature = "alloc")]
pub use secret::SecretVec;

// Re-export memory safety traits and utilities
pub use memory::{
    SecureOperation, 
    SecureCompare, 
    SecureOperationExt,
    SecureOperationBuilder,
};

// Re-export memory barrier utilities
pub use memory::barrier;