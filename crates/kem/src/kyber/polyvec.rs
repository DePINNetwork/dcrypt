// kem/src/kyber/polyvec.rs

//! Polynomial vector operations for Kyber.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use algorithms::poly::polynomial::Polynomial;
use algorithms::poly::params::Modulus; // Add this import
use algorithms::error::Result as AlgoResult;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::params::{KyberParams, KyberPolyModParams};

/// A vector of polynomials, typically of dimension K.
#[derive(Debug, PartialEq, Eq, Zeroize)]
pub struct PolyVec<P: KyberParams> {
    /// The polynomials in this vector.
    pub(crate) polys: Vec<Polynomial<KyberPolyModParams>>,
    _params: core::marker::PhantomData<P>,
}

impl<P: KyberParams> Clone for PolyVec<P> {
    fn clone(&self) -> Self {
        Self {
            polys: self.polys.clone(),
            _params: core::marker::PhantomData,
        }
    }
}

impl<P: KyberParams> PolyVec<P> {
    /// Creates a new zero PolyVec of dimension K.
    pub fn zero() -> Self {
        Self {
            polys: vec![Polynomial::<KyberPolyModParams>::zero(); P::K],
            _params: core::marker::PhantomData,
        }
    }
    
    /// Returns the dimension K of this PolyVec.
    pub fn dimension() -> usize {
        P::K
    }

    /// Applies NTT to each polynomial in the vector.
    pub fn ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace()?;
        }
        Ok(())
    }

    /// Applies inverse NTT to each polynomial in the vector.
    pub fn inv_ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.from_ntt_inplace()?;
        }
        Ok(())
    }
    
    /// Computes the pointwise product of two PolyVecs' polynomials,
    /// and accumulates the results into a single polynomial.
    /// Result = sum(self.polys[i] * other.polys[i])
    /// Assumes polynomials are already in NTT domain.
    pub fn pointwise_accum(&self, other: &Self) -> Polynomial<KyberPolyModParams> {
        let mut acc = Polynomial::<KyberPolyModParams>::zero();
        for (p1, p2) in self.polys.iter().zip(other.polys.iter()) {
            let prod = p1.ntt_mul(p2); // p1 and p2 are in NTT domain
            acc = acc.add(&prod);      // Accumulate in NTT domain
        }
        acc // Result is in NTT domain
    }

    /// Adds another PolyVec to this one, coefficient-wise.
    pub fn add_assign(&mut self, other: &Self) {
        for (p1, p2) in self.polys.iter_mut().zip(other.polys.iter()) {
            *p1 = p1.add(p2);
        }
    }

    /// Subtracts another PolyVec from this one, coefficient-wise.
    pub fn sub_assign(&mut self, other: &Self) {
        for (p1, p2) in self.polys.iter_mut().zip(other.polys.iter()) {
            *p1 = p1.sub(p2);
        }
    }
    
    /// Compress polynomial vector
    pub fn compress(&self, du: usize) -> Vec<u8> {
        let mut result = Vec::new();
        let mask = (1u32 << du) - 1;
        
        for poly in &self.polys {
            for &coeff in poly.as_coeffs_slice() {
                // Compress: round(2^du / q * coeff) mod 2^du
                let t = (((coeff as u64) << du) + (KyberPolyModParams::Q as u64 / 2)) / (KyberPolyModParams::Q as u64);
                result.push((t & mask as u64) as u8);
            }
        }
        
        result
    }
    
    /// Decompress polynomial vector
    pub fn decompress(data: &[u8], du: usize, k: usize) -> AlgoResult<Self> {
        let mut polyvec = Self::zero();
        let mut idx = 0;
        
        for i in 0..k {
            for j in 0..KyberPolyModParams::N {
                if idx >= data.len() {
                    return Err(algorithms::error::Error::Processing {
                        operation: "decompress",
                        details: "insufficient data",
                    });
                }
                
                // Decompress: round(q / 2^du * x)
                let x = data[idx] as u32;
                polyvec.polys[i].coeffs[j] = (x * KyberPolyModParams::Q + (1 << (du - 1))) >> du;
                idx += 1;
            }
        }
        
        Ok(polyvec)
    }
    
    /// Pack polynomial vector to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        for poly in &self.polys {
            // Pack each polynomial with 12-bit coefficients
            for chunk in poly.as_coeffs_slice().chunks(2) {
                if chunk.len() == 2 {
                    // Pack two 12-bit values into 3 bytes
                    bytes.push((chunk[0] & 0xFF) as u8);
                    bytes.push((((chunk[0] >> 8) & 0x0F) | ((chunk[1] & 0x0F) << 4)) as u8);
                    bytes.push((chunk[1] >> 4) as u8);
                } else if chunk.len() == 1 {
                    // Pack last coefficient if odd number
                    bytes.push((chunk[0] & 0xFF) as u8);
                    bytes.push(((chunk[0] >> 8) & 0x0F) as u8);
                }
            }
        }
        
        bytes
    }
    
    /// Unpack bytes to polynomial vector
    pub fn from_bytes(bytes: &[u8], k: usize) -> AlgoResult<Self> {
        let mut polyvec = Self::zero();
        let mut byte_idx = 0;
        
        for i in 0..k {
            for j in (0..KyberPolyModParams::N).step_by(2) {
                if byte_idx + 2 >= bytes.len() {
                    return Err(algorithms::error::Error::Processing {
                        operation: "from_bytes",
                        details: "insufficient data",
                    });
                }
                
                // Unpack two 12-bit values from 3 bytes
                let d1 = (bytes[byte_idx] as u32) | ((bytes[byte_idx + 1] as u32 & 0x0F) << 8);
                polyvec.polys[i].coeffs[j] = d1;
                
                if j + 1 < KyberPolyModParams::N {
                    let d2 = ((bytes[byte_idx + 1] as u32) >> 4) | ((bytes[byte_idx + 2] as u32) << 4);
                    polyvec.polys[i].coeffs[j + 1] = d2;
                }
                
                byte_idx += 3;
            }
        }
        
        Ok(polyvec)
    }
}