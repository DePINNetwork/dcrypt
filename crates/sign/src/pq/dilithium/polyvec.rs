//! Polynomial vector types and operations specific to Dilithium.
//!
//! IMPORTANT: This module uses TWO different parameter sets:
//! 1. `algorithms::poly::params::DilithiumParams` - Contains NTT constants for polynomial arithmetic
//! 2. `params::pqc::dilithium::DilithiumSchemeParams` - Contains signature scheme parameters
//!
//! The polynomial type MUST use the algorithms version to get correct NTT scaling factors!

use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_algorithms::poly::params::{DilithiumParams, Modulus};
use dcrypt_algorithms::xof::shake::ShakeXof128;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_algorithms::error::Result as AlgoResult;
use crate::error::{Error as SignError};
use dcrypt_params::pqc::dilithium::DilithiumSchemeParams;
use core::marker::PhantomData;
use zeroize::Zeroize;

// Montgomery reduce is available from algorithms::poly::ntt when needed

// Import centered_sub from arithmetic module
use super::arithmetic::centered_sub;

/// A vector of polynomials of length L (columns of A).
#[derive(Debug)]
pub struct PolyVecL<P: DilithiumSchemeParams> {
    pub(crate) polys: Vec<Polynomial<DilithiumParams>>,
    _params: PhantomData<P>,
}

/// A vector of polynomials of length K (rows of A).
#[derive(Debug)]
pub struct PolyVecK<P: DilithiumSchemeParams> {
    pub(crate) polys: Vec<Polynomial<DilithiumParams>>,
    _params: PhantomData<P>,
}

impl<P: DilithiumSchemeParams> Clone for PolyVecL<P> {
    fn clone(&self) -> Self {
        Self {
            polys: self.polys.clone(),
            _params: PhantomData,
        }
    }
}
impl<P: DilithiumSchemeParams> Clone for PolyVecK<P> {
    fn clone(&self) -> Self {
        Self {
            polys: self.polys.clone(),
            _params: PhantomData,
        }
    }
}

impl<P: DilithiumSchemeParams> Zeroize for PolyVecL<P> {
    fn zeroize(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.coeffs.as_mut_slice().zeroize(); // Zeroes in place, length intact
        }
    }
}
impl<P: DilithiumSchemeParams> Zeroize for PolyVecK<P> {
    fn zeroize(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.coeffs.as_mut_slice().zeroize(); // Zeroes in place, length intact
        }
    }
}

impl<P: DilithiumSchemeParams> PolyVecL<P> {
    /// Creates a new PolyVecL with all coefficients = 0.
    pub fn zero() -> Self {
        let mut polys = Vec::with_capacity(P::L_DIM);
        for _ in 0..P::L_DIM {
            polys.push(Polynomial::<DilithiumParams>::zero());
        }
        Self { polys, _params: PhantomData }
    }

    /// Apply forward NTT in‐place to every polynomial.
    pub fn ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace()?;
        }
        Ok(())
    }

    /// Point-wise product and accumulate into one Polynomial (all in NTT domain).
    pub fn pointwise_dot_product(&self, other: &PolyVecL<P>) -> Polynomial<DilithiumParams> {
        let mut acc = Polynomial::<DilithiumParams>::zero();
        for i in 0..P::L_DIM {
            let prod = self.polys[i].ntt_mul(&other.polys[i]);
            acc = acc.add(&prod);
        }
        acc
    }
}

impl<P: DilithiumSchemeParams> PolyVecK<P> {
    /// Creates a new PolyVecK with all coefficients = 0.
    pub fn zero() -> Self {
        let mut polys = Vec::with_capacity(P::K_DIM);
        for _ in 0..P::K_DIM {
            polys.push(Polynomial::<DilithiumParams>::zero());
        }
        Self { polys, _params: PhantomData }
    }

    /// Apply forward NTT in‐place.
    pub fn ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace()?;
        }
        Ok(())
    }

    /// Apply inverse NTT in‐place.
    pub fn inv_ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            // p.from_ntt_inplace() from algorithms/poly/ntt.rs implements InvNTT_R_logN (FIPS 204 Alg 27),
            // which results in coefficients in standard domain per FIPS 204
            p.from_ntt_inplace()?;
        }
        Ok(())
    }

    /// self + other, element-wise.
    pub fn add(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::K_DIM {
            res.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        res
    }

    /// self − other, element-wise.
    pub fn sub(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::K_DIM {
            res.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        res
    }

    /// Subtract with centered result in (-q/2, q/2]
    /// 
    /// This method performs subtraction where the result is kept in the centered range
    /// (-q/2, q/2] rather than the standard [0, q) range. This is critical for the
    /// hint mechanism in Dilithium to work correctly.
    /// 
    /// The centered subtraction ensures that:
    /// - Small negative differences remain small (e.g., -19000 stays -19000)
    /// - The norm check sees the correct values
    /// - The hint generation works with properly represented values
    pub fn sub_centered(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..P::K_DIM {
            for j in 0..dcrypt_params::pqc::dilithium::DILITHIUM_N {
                let diff = centered_sub(self.polys[i].coeffs[j], other.polys[i].coeffs[j]);
                result.polys[i].coeffs[j] = 
                    ((diff as i64).rem_euclid(DilithiumParams::Q as i64)) as u32;
            }
        }
        result
    }
}



/// Matrix‐vector multiply: Â (K×L) × vec_l̂ (L). All in NTT domain.
/// Returns a K‐vector in NTT domain.
pub fn matrix_polyvecl_mul<P: DilithiumSchemeParams>(
    matrix_a_hat: &[PolyVecL<P>], // K rows, each has L polys in NTT domain
    vector_l_hat: &PolyVecL<P>,   // L polys in NTT domain
) -> PolyVecK<P> {
    let mut result_veck = PolyVecK::<P>::zero();

    for (i, row) in matrix_a_hat.iter().enumerate() {
        result_veck.polys[i] = row.pointwise_dot_product(vector_l_hat);
    }

    result_veck
}

/// Expand a seed `rho_seed` into the matrix A (K × L of polynomials in standard domain).
/// Each polynomial A[i][j] is generated via SHAKE128(rho ∥ j ∥ i).
pub fn expand_matrix_a<P: DilithiumSchemeParams>(
    rho_seed: &[u8; 32], // always 32 bytes
) -> Result<Vec<PolyVecL<P>>, SignError> {
    let mut matrix_a = Vec::with_capacity(P::K_DIM);

    for i in 0..P::K_DIM {
        let mut row = PolyVecL::<P>::zero();
        for j in 0..P::L_DIM {
            let mut xof = ShakeXof128::new();
            xof.update(rho_seed).map_err(SignError::from_algo)?;
            xof.update(&[j as u8]).map_err(SignError::from_algo)?;
            xof.update(&[i as u8]).map_err(SignError::from_algo)?;

            let mut poly = Polynomial::<DilithiumParams>::zero();
            let mut ctr = 0;
            let mut temp_buf = [0u8; 3];

            while ctr < DilithiumParams::N {
                xof.squeeze(&mut temp_buf).map_err(SignError::from_algo)?;
                // Extract two 12-bit values from 3 bytes
                let d1 = (temp_buf[0] as u32) | (((temp_buf[1] as u32) & 0x0F) << 8);
                let d2 = ((temp_buf[1] as u32) >> 4) | ((temp_buf[2] as u32) << 4);

                if d1 < DilithiumParams::Q {
                    poly.coeffs[ctr] = d1;
                    ctr += 1;
                }
                if ctr < DilithiumParams::N && d2 < DilithiumParams::Q {
                    poly.coeffs[ctr] = d2;
                    ctr += 1;
                }
            }

            row.polys[j] = poly;
        }
        matrix_a.push(row);
    }
    Ok(matrix_a)
}