// File: crates/sign/src/pq/dilithium/polyvec.rs
//! Polynomial vector types and operations specific to Dilithium.
//! This module defines `PolyVecL` and `PolyVecK` which are vectors of polynomials
//! of dimension L and K respectively, as specified by the Dilithium parameters.
//! It also includes functions for expanding the matrix A from a seed.

use algorithms::poly::polynomial::Polynomial;
use algorithms::poly::ntt::{NttOperator, InverseNttOperator};
// Assumes DilithiumPolyModParams is now correctly defined in algorithms::poly::params
// and implements NttModulus with correct constants for Dilithium's Q and N.
use algorithms::poly::params::DilithiumPolyModParams;
use algorithms::xof::shake::ShakeXof128;
use algorithms::xof::ExtendableOutputFunction;
use algorithms::error::Result as AlgoResult;
use crate::error::{Error as SignError, Result as SignResult};
use params::pqc::dilithium::{DilithiumParams, DILITHIUM_N, DILITHIUM_Q};
use core::marker::PhantomData;
use zeroize::Zeroize;

/// A vector of `DIM` polynomials, parameterized by `P: DilithiumParams`.
/// Each polynomial is an element of `R_q = Z_q[X]/(X^N+1)`.
/// Used to represent `s1`, `y`, `z` (PolyVecL) and `s2`, `t0`, `t1`, `w0`, `w1`, `h` (PolyVecK).
#[derive(Clone, Debug, Zeroize)]
pub struct PolyVec<P: DilithiumParams, const DIM: usize> {
    /// Array of polynomials.
    pub(crate) polys: [Polynomial<DilithiumPolyModParams>; DIM],
    _params: PhantomData<P>,
}

// Type aliases for PolyVecL (dimension L) and PolyVecK (dimension K).
// These rely on `L_DIM` and `K_DIM` being consts in the `DilithiumParams` trait.
pub type PolyVecL<P> = PolyVec<P, {<P as DilithiumParams>::L_DIM}>;
pub type PolyVecK<P> = PolyVec<P, {<P as DilithiumParams>::K_DIM}>;


impl<P: DilithiumParams, const DIM: usize> PolyVec<P, DIM> {
    /// Creates a new PolyVec with all polynomial coefficients set to zero.
    pub fn zero() -> Self {
        Self {
            polys: [(); DIM].map(|_| Polynomial::<DilithiumPolyModParams>::zero()),
            _params: PhantomData,
        }
    }

    /// Applies Number Theoretic Transform (NTT) to each polynomial in the vector in-place.
    /// Coefficients are transformed from standard to NTT representation (Montgomery form).
    pub fn ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace()?;
        }
        Ok(())
    }

    /// Applies Inverse NTT to each polynomial in the vector in-place.
    /// Coefficients are transformed from NTT representation (Montgomery form) to standard.
    pub fn inv_ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.from_ntt_inplace()?;
        }
        Ok(())
    }

    /// Adds two PolyVecs element-wise: `self + other`.
    /// Assumes polynomials are in the same domain (either both standard or both NTT).
    pub fn add(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..DIM {
            res.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        res
    }
    
    /// Subtracts another PolyVec from this one element-wise: `self - other`.
    /// Assumes polynomials are in the same domain.
    pub fn sub(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..DIM {
            res.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        res
    }

    /// Computes the pointwise product of two PolyVecs (typically in NTT domain)
    /// and accumulates the results into a single polynomial (dot product).
    /// Result = sum_{i=0}^{DIM-1} (self.polys[i] * other.polys[i]),
    /// where `*` is coefficient-wise polynomial multiplication in the NTT domain.
    /// The resulting polynomial is also in NTT domain.
    pub fn pointwise_dot_product(&self, other: &PolyVec<P, DIM>) -> Polynomial<DilithiumPolyModParams> {
        let mut acc = Polynomial::<DilithiumPolyModParams>::zero();
        for i in 0..DIM {
            let prod = self.polys[i].ntt_mul(&other.polys[i]);
            acc = acc.add(&prod); // Polynomial addition in NTT domain
        }
        acc
    }
    
    /// Multiplies each polynomial in this PolyVec by a single polynomial `poly_scalar_ntt`.
    /// Assumes `self.polys[i]` and `poly_scalar_ntt` are in NTT domain.
    /// Used for operations like `c_hat * s1_hat` or `c_hat * t1_hat`.
    pub fn poly_mul_elementwise(&self, poly_scalar_ntt: &Polynomial<DilithiumPolyModParams>) -> Self {
        let mut res = Self::zero();
        for i in 0..DIM {
            res.polys[i] = self.polys[i].ntt_mul(poly_scalar_ntt);
        }
        res
    }
}

/// Expands a seed `rho_seed` into matrix A (K_DIM rows, L_DIM columns of polynomials).
/// Each polynomial A_ij is returned in its standard coefficient representation.
/// The caller is responsible for transforming them to NTT domain if needed.
///
/// # Arguments
/// * `rho_seed`: A 32-byte seed used to generate the matrix pseudo-randomly.
///
/// # Returns
/// A `Result` containing the matrix `A` represented as `[PolyVecL<P>; P::K_DIM]`,
/// or a `SignError` on failure.
///
/// # Implementation Notes (FIPS 203, Algorithm 12: ExpandA)
/// - Uses SHAKE128 as the XOF: `SHAKE128(rho || j || i)` for `A_ij` (note `j` then `i` for domain separation).
/// - Coefficients are sampled uniformly modulo Q. Dilithium uses rejection sampling:
///   sample 3 bytes from SHAKE, interpret as two 12-bit integers `d1, d2`.
///   If `d1 < Q`, it's a coefficient. If `d2 < Q`, it's a coefficient. Repeat until N coefficients are generated.
pub fn expand_matrix_a<P: DilithiumParams>(
    rho_seed: &[u8; P::SEED_RHO_BYTES]
) -> Result<[PolyVecL<P>; P::K_DIM], SignError> {
    let mut matrix_a = [(); P::K_DIM].map(|_| PolyVecL::<P>::zero());

    for i in 0..P::K_DIM { // Row index (0 to k-1)
        for j in 0..P::L_DIM { // Column index (0 to l-1)
            let mut xof = ShakeXof128::new();
            // Domain separation for A_ij is SHAKE128(rho || byte(j) || byte(i))
            // Note the order: j then i for standard A_ij indexing.
            xof.update(rho_seed).map_err(SignError::from_algo)?;
            xof.update(&[j as u8, i as u8]).map_err(SignError::from_algo)?;
            
            let mut poly = Polynomial::<DilithiumPolyModParams>::zero();
            let mut ctr = 0; // Coefficient counter for current polynomial
            let mut temp_buf = [0u8; 3]; // Buffer for 3 bytes from SHAKE output

            while ctr < DILITHIUM_N {
                xof.squeeze(&mut temp_buf).map_err(SignError::from_algo)?;
                
                // Extract two 12-bit values d1, d2 from 3 bytes
                // d1 = buf[0] + 2^8 * (buf[1] mod 16)
                let val1 = (temp_buf[0] as u32) | ((temp_buf[1] as u32 & 0x0F) << 8);
                // d2 = floor(buf[1] / 16) + 2^4 * buf[2]
                let val2 = ((temp_buf[1] >> 4) as u32) | ((temp_buf[2] as u32) << 4);

                if val1 < (DILITHIUM_Q as u32) {
                    poly.coeffs[ctr] = val1;
                    ctr += 1;
                }
                if ctr < DILITHIUM_N && val2 < (DILITHIUM_Q as u32) {
                    poly.coeffs[ctr] = val2;
                    ctr += 1;
                }
            }
            matrix_a[i].polys[j] = poly;
        }
    }
    Ok(matrix_a)
}