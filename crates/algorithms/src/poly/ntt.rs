//! ntt.rs - Number Theoretic Transform implementation
//!
//! This module implements Kyber's constant-geometry NTT with Montgomery arithmetic.
//! 
//! ## Montgomery Form Conversions:
//! - Standard → Montgomery: montgomery_mul(a, R²) = a·R
//! - Montgomery → Standard: montgomery_reduce(a_R) = a
//! - Core NTT/InvNTT functions work entirely in Montgomery form
//!
//! ## Constant-Geometry Pattern:
//! Each block of butterflies shares the same twiddle factor, allowing for
//! consistent memory access patterns across all stages.

#![cfg_attr(not(feature = "std"), no_std)]

use super::polynomial::Polynomial;
use super::params::{Modulus, NttModulus}; // FIXED: Import NttModulus from params instead of defining duplicate
use crate::error::{Result, Error};

/// Modular exponentiation. Works in the *standard* domain because the result is
/// converted to Montgomery form before it is actually used.
#[inline(always)]
fn pow_mod<M: Modulus>(mut base: u32, mut exp: u32) -> u32 {
    let mut acc: u32 = 1;
    while exp != 0 {
        if (exp & 1) == 1 {
            acc = ((acc as u64 * base as u64) % M::Q as u64) as u32;
        }
        base = ((base as u64 * base as u64) % M::Q as u64) as u32;
        exp >>= 1;
    }
    acc
}

// REMOVED: Duplicate NttModulus trait definition that was here

/// Trait for forward Number Theoretic Transform
pub trait NttOperator<M: NttModulus> {
    /// Performs the forward NTT on a polynomial
    /// Expects input in Montgomery form, produces output in Montgomery form
    fn ntt(poly: &mut Polynomial<M>) -> Result<()>;
}

/// Trait for inverse Number Theoretic Transform
pub trait InverseNttOperator<M: NttModulus> {
    /// Performs the inverse NTT on a polynomial
    /// Expects input in Montgomery form, produces output in Montgomery form
    fn inv_ntt(poly: &mut Polynomial<M>) -> Result<()>;
}

/// Cooley-Tukey NTT implementation
pub struct CooleyTukeyNtt;

/// Montgomery reduction: computes a * R^-1 mod Q
#[inline(always)]
pub fn montgomery_reduce<M: NttModulus>(a: u64) -> u32 {
    let q = M::Q as u64;
    let q_inv_neg = M::Q_INV_NEG as u64;
    
    let m = ((a as u32) as u64).wrapping_mul(q_inv_neg) & 0xFFFFFFFF;
    let t = a.wrapping_add(m.wrapping_mul(q)) >> 32;
    
    // Branch-free conditional subtraction
    let result = t as u32;
    let mask = ((result >= M::Q) as u32).wrapping_neg();
    result.wrapping_sub(M::Q & mask)
}

/// Montgomery multiplication: computes a * b * R^-1 mod Q
#[inline(always)]
fn montgomery_mul<M: NttModulus>(a: u32, b: u32) -> u32 {
    montgomery_reduce::<M>((a as u64) * (b as u64))
}

/// Modular addition with constant-time reduction
#[inline(always)]
fn add_mod<M: NttModulus>(a: u32, b: u32) -> u32 {
    let t = a.wrapping_add(b);
    t - ((t >= M::Q) as u32) * M::Q
}

/// Modular subtraction with constant-time reduction
#[inline(always)]
fn sub_mod<M: NttModulus>(a: u32, b: u32) -> u32 {
    let t = a.wrapping_sub(b).wrapping_add(M::Q);
    t - ((t >= M::Q) as u32) * M::Q
}

impl<M: NttModulus> NttOperator<M> for CooleyTukeyNtt {
    fn ntt(poly: &mut Polynomial<M>) -> Result<()> {
        let n = M::N;
        if n & (n - 1) != 0 {
            return Err(Error::Parameter {
                name: "NTT".into(),
                reason: "Polynomial degree must be a power of 2".into(),
            });
        }
        
        let coeffs = poly.as_mut_coeffs_slice();
        
        // *** generic NTT with on-the-fly twiddle generation (DIT) ***
        // The coefficients are already in Montgomery form when we enter.
        let mut len = 1_usize;
        while len < n {
            // ω_len = ζ^(N / (2·len))  in *standard* domain …
            let root   = pow_mod::<M>(M::ZETA, (n / (len << 1)) as u32);
            // … convert it to Montgomery domain: root * R mod Q
            // NOT montgomery_mul because that would give root * R * R^-1 = root
            let root_m = ((root as u64 * M::MONT_R as u64) % M::Q as u64) as u32;

            for start in (0..n).step_by(len << 1) {
                // running twiddle inside one block
                let mut w_m = M::MONT_R;        // 1·R   (Montgomery form of 1)
                for j in 0..len {
                    let u = coeffs[start + j];
                    let v = montgomery_mul::<M>(coeffs[start + j + len], w_m);

                    coeffs[start + j]         = add_mod::<M>(u, v);
                    coeffs[start + j + len]   = sub_mod::<M>(u, v);

                    w_m = montgomery_mul::<M>(w_m, root_m);
                }
            }
            len <<= 1;
        }
        
        Ok(())
    }
}

impl<M: NttModulus> InverseNttOperator<M> for CooleyTukeyNtt {
    fn inv_ntt(poly: &mut Polynomial<M>) -> Result<()> {
        let n = M::N;
        if n & (n - 1) != 0 {
            return Err(Error::Parameter {
                name: "Inverse NTT".into(),
                reason: "Polynomial degree must be a power of 2".into(),
            });
        }
        
        let coeffs = poly.as_mut_coeffs_slice();
        
        // *** Gentleman–Sande inverse with on-the-fly twiddles (DIF) ***
        let root_inv = pow_mod::<M>(M::ZETA, (M::Q - 2) as u32); // ζ⁻¹
        let mut len  = n >> 1;
        while len >= 1 {
            // ω_len = ζ⁻¹^(N / (2·len))
            let root   = pow_mod::<M>(root_inv, (n / (len << 1)) as u32);
            // Convert to Montgomery form properly
            let root_m = ((root as u64 * M::MONT_R as u64) % M::Q as u64) as u32;

            for start in (0..n).step_by(len << 1) {
                let mut w_m = M::MONT_R; // 1·R
                for j in 0..len {
                    // Gentleman–Sande butterfly: twiddle AFTER the subtraction
                    let u = coeffs[start + j];
                    let v = coeffs[start + j + len];

                    coeffs[start + j]       = add_mod::<M>(u, v);
                    let diff                = sub_mod::<M>(u, v);
                    coeffs[start + j + len] = montgomery_mul::<M>(diff, w_m);

                    w_m = montgomery_mul::<M>(w_m, root_m);
                }
            }
            len >>= 1;
        }

        // Final scaling by N^-1
        // N_INV is in Montgomery form: (256^-1 · R) mod Q
        // After this, coefficients are still in Montgomery form
        for c in coeffs.iter_mut() {
            *c = montgomery_mul::<M>(*c, M::N_INV);
        }
        
        Ok(())
    }
}

/// Extension methods for Polynomial to support NTT operations
impl<M: NttModulus> Polynomial<M> {
    /// Convert polynomial to NTT domain in-place
    /// Forward NTT (standard → Montgomery, bit-reversed)
    pub fn ntt_inplace(&mut self) -> Result<()> {
        // Convert coefficients to Montgomery form: a → a·R mod Q
        // We use montgomery_mul(a, R²) = a·R²·R⁻¹ = a·R
        // For Kyber: R = 1353, R² = 1353² mod 3329 = 2988
        let r2 = ((M::MONT_R as u64 * M::MONT_R as u64) % M::Q as u64) as u32;
        
        for c in self.as_mut_coeffs_slice() {
            *c = montgomery_mul::<M>(*c, r2);
        }
        
        // Apply Cooley-Tukey NTT
        CooleyTukeyNtt::ntt(self)
    }
    
    /// Convert polynomial from NTT domain in-place
    /// Inverse NTT (Montgomery/bit-reversed → standard/natural order)
    pub fn from_ntt_inplace(&mut self) -> Result<()> {
        // Apply Gentleman-Sande inverse NTT
        CooleyTukeyNtt::inv_ntt(self)?;
        
        // Convert back from Montgomery domain to standard form
        // montgomery_reduce(a_R) = a_R · R⁻¹ = a
        for c in self.as_mut_coeffs_slice() {
            *c = montgomery_reduce::<M>(*c as u64);
        }
        
        Ok(())
    }
    
    /// Multiply two polynomials in NTT domain (pointwise multiplication)
    /// Expects both polynomials in Montgomery form, NTT domain
    /// Result will also be in Montgomery form, NTT domain
    pub fn ntt_mul(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        let n = M::N;
        
        for i in 0..n {
            result.coeffs[i] = montgomery_mul::<M>(self.coeffs[i], other.coeffs[i]);
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Test parameters for Kyber-256
    #[derive(Clone)]
    struct KyberTestModulus;
    
    impl Modulus for KyberTestModulus {
        const Q: u32 = 3329;
        const N: usize = 256;
    }
    
    // Same tables/parameters as production Kyber-256, but scoped locally for the unit-tests
    impl NttModulus for KyberTestModulus {
        const ZETA: u32 = 17;
        // Tables removed – on-the-fly twiddle generation is used instead
        const ZETAS: &'static [u32] = &[];
        const INV_ZETAS: &'static [u32] = &[];
        
        const N_INV: u32 = 2385;         // 256^-1 · R_32 mod 3329
        const MONT_R: u32 = 1353;        // 2^32 mod Q
        const Q_INV_NEG: u32 = 0x94570CFF; // -Q^-1 mod 2^32
    }
    
    #[test]
    fn test_ntt_inverse_identity() {
        // Test that inv_ntt(ntt(p)) == p
        let mut poly = Polynomial::<KyberTestModulus>::zero();
        poly.coeffs[0] = 1;
        poly.coeffs[1] = 2;
        poly.coeffs[2] = 3;
        
        let original = poly.clone();
        
        // Forward NTT
        poly.ntt_inplace().unwrap();
        
        // Inverse NTT
        poly.from_ntt_inplace().unwrap();
        
        // Should recover original polynomial
        for i in 0..original.coeffs.len() {
            assert_eq!(poly.coeffs[i], original.coeffs[i], 
                      "Coefficient {} mismatch", i);
        }
    }
    
    #[test]
    fn test_montgomery_reduction() {
        // Test basic Montgomery reduction
        let a: u64 = 1234;
        let reduced = montgomery_reduce::<KyberTestModulus>(a);
        assert!(reduced < KyberTestModulus::Q);
    }
}