//! BLS12-381 pairing-friendly elliptic curve implementation.
//!
//! **Warning:** Unaudited implementation. Use at your own risk.

// External crates
#[cfg(feature = "alloc")]
extern crate alloc;

// Module declarations
mod field;
mod g1;
mod g2;
mod pairings;
mod scalar;

#[cfg(test)]
mod tests;

// Internal use for submodules
use scalar::Scalar;

// Public API exports (following dcrypt conventions)
pub use g1::{G1Affine, G1Projective};
pub use g2::{G2Affine, G2Projective};
pub use pairings::{pairing, Bls12, Gt, MillerLoopResult};
pub use self::scalar::Scalar as Bls12_381Scalar;
// Remove the duplicate: pub use self::scalar::Scalar;

#[cfg(feature = "alloc")]
pub use pairings::{multi_miller_loop, G2Prepared};

// BLS curve parameters
/// BLS parameter x = -0xd201000000010000
const BLS_X: u64 = 0xd201_0000_0001_0000;
/// Sign of BLS parameter x
const BLS_X_IS_NEGATIVE: bool = true;