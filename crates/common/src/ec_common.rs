//! Common elliptic curve operations

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

/// Point on an elliptic curve
#[cfg(any(feature = "std", feature = "alloc"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
    pub z: Option<Vec<u8>>,  // For projective coordinates (None for affine)
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl Point {
    /// Create a new affine point (x, y)
    pub fn new_affine(x: Vec<u8>, y: Vec<u8>) -> Self {
        Self {
            x,
            y,
            z: None,
        }
    }
    
    /// Create a new projective point (x, y, z)
    pub fn new_projective(x: Vec<u8>, y: Vec<u8>, z: Vec<u8>) -> Self {
        Self {
            x,
            y,
            z: Some(z),
        }
    }
    
    /// Check if this is the point at infinity
    pub fn is_infinity(&self) -> bool {
        match &self.z {
            Some(z) => z.iter().all(|&b| b == 0),
            None => self.x.is_empty() && self.y.is_empty(),
        }
    }
}

/// Elliptic curve parameters in short Weierstrass form: y^2 = x^3 + ax + b
#[cfg(any(feature = "std", feature = "alloc"))]
#[derive(Clone, Debug)]
pub struct CurveParams {
    /// The 'a' coefficient
    pub a: Vec<u8>,
    
    /// The 'b' coefficient
    pub b: Vec<u8>,
    
    /// The prime field modulus
    pub p: Vec<u8>,
    
    /// The order of the curve (number of points)
    pub order: Vec<u8>,
    
    /// The cofactor
    pub cofactor: Vec<u8>,
    
    /// Generator point
    pub generator: Point,
}