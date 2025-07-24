//! Multivariate Quadratic (MQ) Cryptosystem Primitives
//!
//! This module is a placeholder for mathematical primitives required by
//! MQ-based signature schemes like Rainbow.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod gf256;
pub mod quadratic;
pub mod solve;

// pub use gf256::Gf256Element;
// pub use quadratic::MultivariateQuadraticSystem;
// pub use solve::SystemSolver;
