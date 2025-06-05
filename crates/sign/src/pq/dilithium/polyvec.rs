//! Polynomial vector types and operations specific to Dilithium.

use algorithms::poly::polynomial::Polynomial;
use algorithms::poly::params::{DilithiumParams, Modulus, NttModulus};
use algorithms::xof::shake::ShakeXof128;
use algorithms::xof::ExtendableOutputFunction;
use algorithms::error::Result as AlgoResult;
use crate::error::{Error as SignError};
use params::pqc::dilithium::DilithiumParams as DilithiumSignParams;
use core::marker::PhantomData;
use zeroize::Zeroize;

/// A vector of polynomials for dimension L (columns in matrix A)
#[derive(Debug)]
pub struct PolyVecL<P: DilithiumSignParams> {
    pub(crate) polys: Vec<Polynomial<DilithiumParams>>,
    _params: PhantomData<P>,
}

/// A vector of polynomials for dimension K (rows in matrix A)
#[derive(Debug)]
pub struct PolyVecK<P: DilithiumSignParams> {
    pub(crate) polys: Vec<Polynomial<DilithiumParams>>,
    _params: PhantomData<P>,
}

// Implement Clone manually to avoid trait bound issues
impl<P: DilithiumSignParams> Clone for PolyVecL<P> {
    fn clone(&self) -> Self {
        Self {
            polys: self.polys.clone(),
            _params: PhantomData,
        }
    }
}

impl<P: DilithiumSignParams> Clone for PolyVecK<P> {
    fn clone(&self) -> Self {
        Self {
            polys: self.polys.clone(),
            _params: PhantomData,
        }
    }
}

impl<P: DilithiumSignParams> Zeroize for PolyVecL<P> {
    fn zeroize(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.coeffs.zeroize();
        }
    }
}

impl<P: DilithiumSignParams> Zeroize for PolyVecK<P> {
    fn zeroize(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.coeffs.zeroize();
        }
    }
}

impl<P: DilithiumSignParams> PolyVecL<P> {
    /// Creates a new PolyVecL with all polynomial coefficients set to zero.
    pub fn zero() -> Self {
        Self {
            polys: vec![Polynomial::<DilithiumParams>::zero(); P::L_DIM],
            _params: PhantomData,
        }
    }

    /// Applies Number Theoretic Transform (NTT) to each polynomial in the vector in-place.
    pub fn ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace()?;
        }
        Ok(())
    }

    /// Applies Inverse NTT to each polynomial in the vector in-place.
    pub fn inv_ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.from_ntt_inplace()?;
        }
        Ok(())
    }

    /// Adds two PolyVecs element-wise: `self + other`.
    pub fn add(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::L_DIM {
            res.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        res
    }
    
    /// Subtracts another PolyVec from this one element-wise: `self - other`.
    pub fn sub(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::L_DIM {
            res.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        res
    }

    /// Computes the pointwise product of two PolyVecs and accumulates into a single polynomial.
    /// Result = sum_{i=0}^{L_DIM-1} (self.polys[i] * other.polys[i]).
    /// Both inputs must be in NTT domain; result is also in NTT domain.
    pub fn pointwise_dot_product(&self, other: &PolyVecL<P>) -> Polynomial<DilithiumParams> {
        let mut acc = Polynomial::<DilithiumParams>::zero();
        for i in 0..P::L_DIM {
            let prod = self.polys[i].ntt_mul(&other.polys[i]);
            acc = acc.add(&prod);
        }
        acc
    }
    
    /// Multiplies each polynomial in this PolyVec by a single polynomial.
    /// Assumes both are in NTT domain.
    pub fn poly_mul_elementwise(&self, poly_scalar_ntt: &Polynomial<DilithiumParams>) -> Self {
        let mut res = Self::zero();
        for i in 0..P::L_DIM {
            res.polys[i] = self.polys[i].ntt_mul(poly_scalar_ntt);
        }
        res
    }
}

impl<P: DilithiumSignParams> PolyVecK<P> {
    /// Creates a new PolyVecK with all polynomial coefficients set to zero.
    pub fn zero() -> Self {
        Self {
            polys: vec![Polynomial::<DilithiumParams>::zero(); P::K_DIM],
            _params: PhantomData,
        }
    }

    /// Applies Number Theoretic Transform (NTT) to each polynomial in the vector in-place.
    pub fn ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace()?;
        }
        Ok(())
    }

    /// Applies Inverse NTT to each polynomial in the vector in-place.
    pub fn inv_ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.from_ntt_inplace()?;
        }
        Ok(())
    }

    /// Adds two PolyVecs element-wise: `self + other`.
    pub fn add(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::K_DIM {
            res.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        res
    }
    
    /// Subtracts another PolyVec from this one element-wise: `self - other`.
    pub fn sub(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::K_DIM {
            res.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        res
    }
}

/// Matrix-vector multiplication: A_hat * vec_l
/// where A_hat is a K×L matrix of polynomials in NTT domain
/// and vec_l is an L-vector of polynomials in NTT domain.
/// Result is a K-vector of polynomials in NTT domain.
pub fn matrix_polyvecl_mul<P: DilithiumSignParams>(
    matrix_a_hat: &[PolyVecL<P>], // K rows, each row has L polynomials
    vector_l_hat: &PolyVecL<P>     // L polynomials
) -> PolyVecK<P> {
    let mut result_veck = PolyVecK::<P>::zero();
    
    // For each row i of the matrix (output element i)
    for (i, row) in matrix_a_hat.iter().enumerate() {
        // Compute dot product of row i with the vector
        result_veck.polys[i] = row.pointwise_dot_product(vector_l_hat);
    }
    
    result_veck
}

/// Expands a seed `rho_seed` into matrix A (K_DIM rows, L_DIM columns of polynomials).
/// Each polynomial A[i][j] is generated using SHAKE128(rho || j || i).
/// Returns polynomials in standard domain.
pub fn expand_matrix_a<P: DilithiumSignParams>(
    rho_seed: &[u8; 32] // SEED_RHO_BYTES is always 32
) -> Result<Vec<PolyVecL<P>>, SignError> {
    let mut matrix_a = Vec::with_capacity(P::K_DIM);

    for i in 0..P::K_DIM {    // Row index (0 to k-1)
        let mut row = PolyVecL::<P>::zero();
        
        for j in 0..P::L_DIM { // Column index (0 to l-1)
            let mut xof = ShakeXof128::new();
            // Domain separation: SHAKE128(rho || j || i)
            xof.update(rho_seed).map_err(SignError::from_algo)?;
            xof.update(&[j as u8]).map_err(SignError::from_algo)?;
            xof.update(&[i as u8]).map_err(SignError::from_algo)?;
            
            let mut poly = Polynomial::<DilithiumParams>::zero();
            let mut ctr = 0;
            let mut temp_buf = [0u8; 3];

            // Sample coefficients using rejection sampling
            while ctr < DilithiumParams::N {
                xof.squeeze(&mut temp_buf).map_err(SignError::from_algo)?;
                
                // Extract two 12-bit values from 3 bytes
                // d1 = buf[0] + 2^8 * (buf[1] mod 16)
                let d1 = (temp_buf[0] as u32) | ((temp_buf[1] as u32 & 0x0F) << 8);
                // d2 = floor(buf[1] / 16) + 2^4 * buf[2]
                let d2 = ((temp_buf[1] >> 4) as u32) | ((temp_buf[2] as u32) << 4);

                // Accept if less than Q
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