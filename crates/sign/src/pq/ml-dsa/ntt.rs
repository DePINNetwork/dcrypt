//! ntt.rs - Simple and Robust NTT Implementation
//!
//! Key insight: Keep it simple and follow standard NTT patterns
//! FIXED: Match test expectations for domain handling

#![cfg_attr(not(feature = "std"), no_std)]

use super::polynomial::Polynomial;
use super::params::{Modulus, NttModulus, PostInvNtt};
use crate::error::{Result, Error};

/// Modular exponentiation in standard domain
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

/// Trait for forward Number Theoretic Transform
pub trait NttOperator<M: NttModulus> {
    /// Performs the forward NTT (scheme-adaptive)
    fn ntt(poly: &mut Polynomial<M>) -> Result<()>;
}

/// Trait for inverse Number Theoretic Transform
pub trait InverseNttOperator<M: NttModulus> {
    /// Performs the inverse NTT (scheme-adaptive)
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
fn add_mod<M: Modulus>(a: u32, b: u32) -> u32 {
    let t = a.wrapping_add(b);
    t - ((t >= M::Q) as u32) * M::Q
}

/// Modular subtraction with constant-time reduction
#[inline(always)]
fn sub_mod<M: Modulus>(a: u32, b: u32) -> u32 {
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
        let needs_twist = !M::ZETAS.is_empty();

        if needs_twist {
            // ─────────── Dilithium NTT (FIPS-204 Algorithm 41) ───────────
            // Convert input to Montgomery domain for consistent arithmetic
            for c in coeffs.iter_mut() {
                *c = ((*c as u64 * M::MONT_R as u64) % M::Q as u64) as u32;
            }
            
            // Follow reference implementation exactly - use Montgomery arithmetic throughout
            let mut m = 0;
            for len in [128, 64, 32, 16, 8, 4, 2, 1] {
                for start in (0..n).step_by(2 * len) {
                    m += 1;
                    // Convert ζ once: ζ_mont = ζ_std · R  (NO Montgomery-reduce!)
                    let zeta = ((M::ZETAS[m] as u64 * M::MONT_R as u64) % M::Q as u64) as u32;
                    
                    for j in start..(start + len) {
                        let t = montgomery_mul::<M>(zeta, coeffs[j + len]);
                        coeffs[j + len] = sub_mod::<M>(coeffs[j], t);
                        coeffs[j] = add_mod::<M>(coeffs[j], t);
                    }
                }
            }
        } else {
            // ─────────── Kyber NTT (Cooley-Tukey) ───────────
            // Convert input to Montgomery domain for Montgomery arithmetic
            for c in coeffs.iter_mut() {
                *c = ((*c as u64 * M::MONT_R as u64) % M::Q as u64) as u32;
            }
            
            let mut len = 1_usize;
            while len < n {
                let exp = n / (len << 1);
                let root_std = pow_mod::<M>(M::ZETA, exp as u32);
                let root_mont = ((root_std as u64 * M::MONT_R as u64) % M::Q as u64) as u32;

                for start in (0..n).step_by(len << 1) {
                    let mut w_mont = M::MONT_R; // 1 in Montgomery form
                    
                    for j in 0..len {
                        let u = coeffs[start + j];
                        let v = montgomery_mul::<M>(coeffs[start + j + len], w_mont);

                        coeffs[start + j] = add_mod::<M>(u, v);
                        coeffs[start + j + len] = sub_mod::<M>(u, v);

                        w_mont = montgomery_mul::<M>(w_mont, root_mont);
                    }
                }
                len <<= 1;
            }
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
        let needs_twist = !M::ZETAS.is_empty();

        if needs_twist {
            // ─────────── Dilithium Inverse NTT (FIPS-204 Algorithm 42) ───────────
            // Follow reference implementation exactly with Montgomery arithmetic
            let mut m = 256;
            for len in [1, 2, 4, 8, 16, 32, 64, 128] {
                for start in (0..n).step_by(2 * len) {
                    m -= 1;
                    // Same one-shot conversion as in the forward path
                    let zeta = ((M::ZETAS[m] as u64 * M::MONT_R as u64) % M::Q as u64) as u32;
                    
                    for j in start..(start + len) {
                        let t = coeffs[j];
                        coeffs[j] = add_mod::<M>(t, coeffs[j + len]);
                        coeffs[j + len] = montgomery_mul::<M>(zeta, sub_mod::<M>(t, coeffs[j + len]));
                    }
                }
            }
            
            // Final scaling by N^-1 (already in Montgomery form)
            for c in coeffs.iter_mut() {
                *c = montgomery_mul::<M>(*c, M::N_INV);
            }
            
            // FIXED: Simplified domain conversion
            // Keep coefficients in Montgomery domain for Dilithium
            // POST_INVNTT_MODE = Montgomery means no further conversion needed
            if M::POST_INVNTT_MODE == PostInvNtt::Standard {
                for c in coeffs.iter_mut() {
                    *c = montgomery_reduce::<M>(*c as u64);
                }
            }
        } else {
            // ─────────── Kyber Inverse NTT ───────────
            let root_inv_std = pow_mod::<M>(M::ZETA, (M::Q - 2) as u32);
            
            let mut len = n >> 1;
            while len >= 1 {
                let exp = n / (len << 1);
                let root_std = pow_mod::<M>(root_inv_std, exp as u32);
                let root_mont = ((root_std as u64 * M::MONT_R as u64) % M::Q as u64) as u32;

                for start in (0..n).step_by(len << 1) {
                    let mut w_mont = M::MONT_R;
                    
                    for j in 0..len {
                        let u = coeffs[start + j];
                        let v = coeffs[start + j + len];

                        coeffs[start + j] = add_mod::<M>(u, v);
                        coeffs[start + j + len] = montgomery_mul::<M>(sub_mod::<M>(u, v), w_mont);

                        w_mont = montgomery_mul::<M>(w_mont, root_mont);
                    }
                }
                len >>= 1;
            }

            // Scale by N^(-1) in Montgomery domain
            for c in coeffs.iter_mut() {
                *c = montgomery_mul::<M>(*c, M::N_INV);
            }
            
            // Convert to standard domain
            for c in coeffs.iter_mut() {
                *c = montgomery_reduce::<M>(*c as u64);
            }
        }
        
        Ok(())
    }
}

/// Extension methods for Polynomial supporting both cyclic and twisted negacyclic NTT
impl<M: NttModulus> Polynomial<M> {
    /// Convert polynomial to NTT domain (scheme-appropriate)
    pub fn ntt_inplace(&mut self) -> Result<()> {
        CooleyTukeyNtt::ntt(self)
    }

    /// Convert polynomial from NTT domain (scheme-appropriate)
    pub fn from_ntt_inplace(&mut self) -> Result<()> {
        CooleyTukeyNtt::inv_ntt(self)
    }

    /// Pointwise multiplication in NTT domain
    pub fn ntt_mul(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        let n = M::N;
        
        // Both Kyber and Dilithium use Montgomery multiplication in NTT domain
        for i in 0..n {
            result.coeffs[i] = montgomery_mul::<M>(self.coeffs[i], other.coeffs[i]);
        }
        
        result
    }
}

#[cfg(test)]
mod tests;