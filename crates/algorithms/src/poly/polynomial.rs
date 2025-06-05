//! polynomial.rs - Enhanced implementation with arithmetic operations

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use core::marker::PhantomData;
use core::ops::{Add, Sub, Neg, Mul};
use super::params::{Modulus, NttModulus}; // FIXED: Import NttModulus from params
use super::ntt::montgomery_reduce;
use crate::error::{Result, Error};
use zeroize::Zeroize;

/// A polynomial in a ring R_Q = Z_Q[X]/(X^N + 1)
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct Polynomial<M: Modulus> {
    /// Coefficients of the polynomial, stored in standard representation
    #[cfg(feature = "alloc")]
    pub coeffs: Vec<u32>,
    /// Coefficients of the polynomial, stored in standard representation
    #[cfg(not(feature = "alloc"))]
    pub coeffs: [u32; 256], // Will need const generics for proper support
    _marker: PhantomData<M>,
}

impl<M: Modulus> Polynomial<M> {
    /// Creates a new polynomial with all coefficients set to zero
    pub fn zero() -> Self {
        Self {
            #[cfg(feature = "alloc")]
            coeffs: vec![0; M::N],
            #[cfg(not(feature = "alloc"))]
            coeffs: [0; M::N],
            _marker: PhantomData,
        }
    }

    /// Creates a polynomial from a slice of coefficients
    pub fn from_coeffs(coeffs_slice: &[u32]) -> Result<Self> {
        if coeffs_slice.len() != M::N {
            return Err(Error::Parameter {
                name: "coeffs_slice".into(),
                reason: "Incorrect number of coefficients for polynomial degree N".into(),
            });
        }

        #[cfg(feature = "alloc")]
        let coeffs = coeffs_slice.to_vec();
        
        #[cfg(not(feature = "alloc"))]
        let mut coeffs = [0u32; 256];
        #[cfg(not(feature = "alloc"))]
        coeffs[..M::N].copy_from_slice(coeffs_slice);

        Ok(Self {
            coeffs,
            _marker: PhantomData,
        })
    }

    /// Returns the degree N of the polynomial
    pub fn degree() -> usize {
        M::N
    }

    /// Returns the modulus Q for coefficient arithmetic
    pub fn modulus_q() -> u32 {
        M::Q
    }

    /// Returns a slice view of the coefficients
    pub fn as_coeffs_slice(&self) -> &[u32] {
        &self.coeffs[..M::N]
    }

    /// Returns a mutable slice view of the coefficients
    pub fn as_mut_coeffs_slice(&mut self) -> &mut [u32] {
        &mut self.coeffs[..M::N]
    }

    /// Branch-free modular reduction of a single coefficient
    #[inline(always)]
    fn reduce_coefficient(a: u32) -> u32 {
        // Branch-free reduction: a - Q if a >= Q else a
        let q = M::Q;
        let mask = ((a >= q) as u32).wrapping_neg();
        a.wrapping_sub(q & mask)
    }

    /// Branch-free conditional subtraction for signed results
    #[inline(always)]
    fn conditional_sub_q(a: i64) -> u32 {
        let q = M::Q as i64;
        // If a < 0, add Q; if a >= Q, subtract Q
        let a_neg_mask = (a >> 63) as u64;
        let a_geq_q_mask = ((a >= q) as u64).wrapping_neg();
        
        let adjusted = a + (q & a_neg_mask as i64) - (q & a_geq_q_mask as i64);
        adjusted as u32
    }

    /// Polynomial addition modulo Q
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..M::N {
            let sum = self.coeffs[i].wrapping_add(other.coeffs[i]);
            result.coeffs[i] = Self::reduce_coefficient(sum);
        }
        result
    }

    /// Polynomial subtraction modulo Q
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..M::N {
            let diff = (self.coeffs[i] as i64) - (other.coeffs[i] as i64);
            result.coeffs[i] = Self::conditional_sub_q(diff);
        }
        result
    }

    /// Polynomial negation modulo Q
    pub fn neg(&self) -> Self {
        let mut result = Self::zero();
        for i in 0..M::N {
            // Mask is 0xFFFF_FFFF when coeff ≠ 0, 0 otherwise
            let mask = ((self.coeffs[i] != 0) as u32).wrapping_neg();
            result.coeffs[i] = (M::Q - self.coeffs[i]) & mask;
        }
        result
    }

    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: u32) -> Self {
        let mut result = Self::zero();
        for i in 0..M::N {
            let prod = (self.coeffs[i] as u64) * (scalar as u64);
            result.coeffs[i] = (prod % M::Q as u64) as u32;
        }
        result
    }

    /// Schoolbook polynomial multiplication (for correctness testing)
    pub fn schoolbook_mul(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        
        // Compute convolution
        for i in 0..M::N {
            for j in 0..M::N {
                let prod = (self.coeffs[i] as u64) * (other.coeffs[j] as u64);
                let idx = i + j;
                
                if idx < M::N {
                    // Normal case: accumulate
                    let acc = (result.coeffs[idx] as u64) + prod;
                    result.coeffs[idx] = (acc % (M::Q as u64)) as u32;
                } else {
                    // Reduction by X^N + 1: subtract from coefficient at idx - N
                    let reduced_idx = idx - M::N;
                    let acc = (result.coeffs[reduced_idx] as i64) - (prod as i64);
                    result.coeffs[reduced_idx] = Self::conditional_sub_q(acc % (M::Q as i64));
                }
            }
        }
        
        result
    }

    /// In-place coefficient reduction to ensure all coefficients are < Q
    pub fn reduce_coeffs(&mut self) {
        for i in 0..M::N {
            self.coeffs[i] = Self::reduce_coefficient(self.coeffs[i]);
        }
    }
}

/// Extension trait for polynomials with NTT-enabled modulus
pub trait PolynomialNttExt<M: NttModulus> {  // FIXED: Now uses params::NttModulus
    /// Fast scalar multiplication using Montgomery reduction
    fn scalar_mul_montgomery(&self, scalar: u32) -> Polynomial<M>;
}

impl<M: NttModulus> PolynomialNttExt<M> for Polynomial<M> {  // FIXED: Now uses params::NttModulus
    fn scalar_mul_montgomery(&self, scalar: u32) -> Polynomial<M> {
        let mut result = Polynomial::<M>::zero();
        for i in 0..M::N {
            let prod = (self.coeffs[i] as u64) * (scalar as u64);
            result.coeffs[i] = montgomery_reduce::<M>(prod);
        }
        result
    }
}

/// Barrett reduction for fast modular arithmetic
#[inline(always)]
pub fn barrett_reduce<M: Modulus>(a: u32) -> u32 {
    // Simplified Barrett reduction
    // In production, would use precomputed Barrett constant
    a % M::Q
}

// Implement standard ops traits for ergonomic usage
impl<M: Modulus> Add for Polynomial<M> {
    type Output = Self;
    
    fn add(self, other: Self) -> Self::Output {
        (&self).add(&other)
    }
}

impl<M: Modulus> Add for &Polynomial<M> {
    type Output = Polynomial<M>;
    
    fn add(self, other: Self) -> Self::Output {
        self.add(other)
    }
}

impl<M: Modulus> Sub for Polynomial<M> {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self::Output {
        (&self).sub(&other)
    }
}

impl<M: Modulus> Sub for &Polynomial<M> {
    type Output = Polynomial<M>;
    
    fn sub(self, other: Self) -> Self::Output {
        self.sub(other)
    }
}

impl<M: Modulus> Neg for Polynomial<M> {
    type Output = Self;
    
    fn neg(self) -> Self::Output {
        (&self).neg()
    }
}

impl<M: Modulus> Neg for &Polynomial<M> {
    type Output = Polynomial<M>;
    
    fn neg(self) -> Self::Output {
        self.neg()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Test modulus for unit tests
    #[derive(Clone)]
    struct TestModulus;
    impl Modulus for TestModulus {
        const Q: u32 = 3329;  // Kyber's Q
        const N: usize = 4;   // Small for testing
    }
    
    #[test]
    fn test_polynomial_creation() {
        let poly = Polynomial::<TestModulus>::zero();
        assert_eq!(poly.as_coeffs_slice(), &[0, 0, 0, 0]);
        
        let coeffs = vec![1, 2, 3, 4];
        let poly = Polynomial::<TestModulus>::from_coeffs(&coeffs).unwrap();
        assert_eq!(poly.as_coeffs_slice(), &[1, 2, 3, 4]);
    }
    
    #[test]
    fn test_polynomial_addition() {
        let a = Polynomial::<TestModulus>::from_coeffs(&[1, 2, 3, 4]).unwrap();
        let b = Polynomial::<TestModulus>::from_coeffs(&[5, 6, 7, 8]).unwrap();
        let c = (&a).add(&b);
        assert_eq!(c.as_coeffs_slice(), &[6, 8, 10, 12]);
    }
    
    #[test]
    fn test_polynomial_subtraction() {
        let a = Polynomial::<TestModulus>::from_coeffs(&[10, 20, 30, 40]).unwrap();
        let b = Polynomial::<TestModulus>::from_coeffs(&[5, 6, 7, 8]).unwrap();
        let c = (&a).sub(&b);
        assert_eq!(c.as_coeffs_slice(), &[5, 14, 23, 32]);
    }
    
    #[test]
    fn test_polynomial_negation() {
        let a = Polynomial::<TestModulus>::from_coeffs(&[1, 2, 0, 4]).unwrap();
        let neg_a = (&a).neg();
        assert_eq!(neg_a.as_coeffs_slice(), &[3328, 3327, 0, 3325]);
    }
    
    #[test]
    fn test_modular_reduction() {
        let a = Polynomial::<TestModulus>::from_coeffs(&[3330, 3331, 3328, 0]).unwrap();
        let mut b = a.clone();
        b.reduce_coeffs();
        assert_eq!(b.as_coeffs_slice(), &[1, 2, 3328, 0]);
    }
}