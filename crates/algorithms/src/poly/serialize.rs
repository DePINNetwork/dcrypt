//! serialize.rs - Polynomial coefficient packing and unpacking

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::polynomial::Polynomial;
use super::params::Modulus;
use crate::error::{Result, Error};

/// Trait for packing polynomial coefficients into a byte array
pub trait CoefficientPacker<M: Modulus> {
    /// Packs the polynomial's coefficients into a byte vector
    fn pack_coeffs(poly: &Polynomial<M>, bits_per_coeff: usize) -> Result<Vec<u8>>;
}

/// Trait for unpacking polynomial coefficients from a byte array
pub trait CoefficientUnpacker<M: Modulus> {
    /// Unpacks coefficients from a byte vector into a new polynomial
    fn unpack_coeffs(bytes: &[u8], bits_per_coeff: usize) -> Result<Polynomial<M>>;
}

/// Default implementation for coefficient serialization
pub struct DefaultCoefficientSerde;

impl<M: Modulus> CoefficientPacker<M> for DefaultCoefficientSerde {
    fn pack_coeffs(poly: &Polynomial<M>, bits_per_coeff: usize) -> Result<Vec<u8>> {
        if bits_per_coeff == 0 || bits_per_coeff > 32 {
            return Err(Error::Parameter {
                name: "coefficient packing".into(),
                reason: format!("bits_per_coeff must be in range [1, 32], got {}", bits_per_coeff).into(),
            });
        }
        
        let n = M::N;
        let total_bits = n * bits_per_coeff;
        let num_bytes = total_bits.div_ceil(8);  // FIXED: Use div_ceil
        let mut packed = vec![0u8; num_bytes];
        
        let coeffs = poly.as_coeffs_slice();
        let mask = (1u32 << bits_per_coeff) - 1;
        
        let mut bit_pos = 0;
        // FIXED: Use iterator instead of indexing
        for &coeff in coeffs.iter().take(n) {
            let masked_coeff = coeff & mask;
            
            // Pack coefficient into byte array
            for bit in 0..bits_per_coeff {
                if (masked_coeff >> bit) & 1 == 1 {
                    let byte_idx = bit_pos / 8;
                    let bit_idx = bit_pos % 8;
                    packed[byte_idx] |= 1 << bit_idx;
                }
                bit_pos += 1;
            }
        }
        
        Ok(packed)
    }
}

impl<M: Modulus> CoefficientUnpacker<M> for DefaultCoefficientSerde {
    fn unpack_coeffs(bytes: &[u8], bits_per_coeff: usize) -> Result<Polynomial<M>> {
        if bits_per_coeff == 0 || bits_per_coeff > 32 {
            return Err(Error::Parameter {
                name: "coefficient unpacking".into(),
                reason: format!("bits_per_coeff must be in range [1, 32], got {}", bits_per_coeff).into(),
            });
        }
        
        let n = M::N;
        let total_bits = n * bits_per_coeff;
        let required_bytes = total_bits.div_ceil(8);  // FIXED: Use div_ceil
        
        if bytes.len() < required_bytes {
            return Err(Error::Parameter {
                name: "coefficient unpacking".into(),
                reason: format!("insufficient bytes: expected {}, got {}", required_bytes, bytes.len()).into(),
            });
        }
        
        let mut poly = Polynomial::<M>::zero();
        let coeffs = poly.as_mut_coeffs_slice();
        let mask = (1u32 << bits_per_coeff) - 1;
        
        let mut bit_pos = 0;
        // FIXED: Use iterator instead of indexing
        for coeff in coeffs.iter_mut().take(n) {
            let mut coeff_value = 0u32;
            
            // Unpack coefficient from byte array
            for bit in 0..bits_per_coeff {
                let byte_idx = bit_pos / 8;
                let bit_idx = bit_pos % 8;
                
                if (bytes[byte_idx] >> bit_idx) & 1 == 1 {
                    coeff_value |= 1 << bit;
                }
                bit_pos += 1;
            }
            
            *coeff = coeff_value & mask;
        }
        
        Ok(poly)
    }
}

/// Helper function to calculate the number of bytes required for packing
#[allow(clippy::manual_div_ceil)]
pub const fn bytes_required(bits_per_coeff: usize, n: usize) -> usize {
    // Note: div_ceil is not const-stable yet, so we use manual implementation
    // This is required for const functions
    (n * bits_per_coeff + 7) / 8
}

/// Optimized packing for common bit widths
impl DefaultCoefficientSerde {
    /// Optimized packing for 10-bit coefficients (Kyber ciphertext)
    pub fn pack_10bit<M: Modulus>(poly: &Polynomial<M>) -> Result<Vec<u8>> {
        let n = M::N;
        let mut packed = vec![0u8; (n * 10) / 8];
        let coeffs = poly.as_coeffs_slice();
        
        for i in (0..n).step_by(4) {
            let c0 = coeffs[i] & 0x3FF;
            let c1 = coeffs[i + 1] & 0x3FF;
            let c2 = coeffs[i + 2] & 0x3FF;
            let c3 = coeffs[i + 3] & 0x3FF;
            
            let idx = (i * 10) / 8;
            packed[idx] = c0 as u8;
            packed[idx + 1] = ((c0 >> 8) | (c1 << 2)) as u8;
            packed[idx + 2] = ((c1 >> 6) | (c2 << 4)) as u8;
            packed[idx + 3] = ((c2 >> 4) | (c3 << 6)) as u8;
            packed[idx + 4] = (c3 >> 2) as u8;
        }
        
        Ok(packed)
    }
    
    /// Optimized unpacking for 10-bit coefficients
    pub fn unpack_10bit<M: Modulus>(bytes: &[u8]) -> Result<Polynomial<M>> {
        let n = M::N;
        if bytes.len() < (n * 10) / 8 {
            return Err(Error::Parameter {
                name: "10-bit unpacking".into(),
                reason: format!("insufficient bytes: expected {}, got {}", (n * 10) / 8, bytes.len()).into(),
            });
        }
        
        let mut poly = Polynomial::<M>::zero();
        let coeffs = poly.as_mut_coeffs_slice();
        
        for i in (0..n).step_by(4) {
            let idx = (i * 10) / 8;
            coeffs[i] = (bytes[idx] as u32) | ((bytes[idx + 1] as u32 & 0x03) << 8);
            coeffs[i + 1] = ((bytes[idx + 1] as u32) >> 2) | ((bytes[idx + 2] as u32 & 0x0F) << 6);
            coeffs[i + 2] = ((bytes[idx + 2] as u32) >> 4) | ((bytes[idx + 3] as u32 & 0x3F) << 4);
            coeffs[i + 3] = ((bytes[idx + 3] as u32) >> 6) | ((bytes[idx + 4] as u32) << 2);
        }
        
        Ok(poly)
    }
    
    /// Optimized packing for 13-bit coefficients (Dilithium)
    pub fn pack_13bit<M: Modulus>(poly: &Polynomial<M>) -> Result<Vec<u8>> {
        let n = M::N;
        let mut packed = vec![0u8; (n * 13) / 8];
        let coeffs = poly.as_coeffs_slice();
        
        for i in (0..n).step_by(8) {
            let idx = (i * 13) / 8;
            
            // Pack 8 coefficients (13 bits each) into 13 bytes
            packed[idx] = coeffs[i] as u8;
            packed[idx + 1] = ((coeffs[i] >> 8) | (coeffs[i + 1] << 5)) as u8;
            packed[idx + 2] = (coeffs[i + 1] >> 3) as u8;
            packed[idx + 3] = ((coeffs[i + 1] >> 11) | (coeffs[i + 2] << 2)) as u8;
            packed[idx + 4] = ((coeffs[i + 2] >> 6) | (coeffs[i + 3] << 7)) as u8;
            packed[idx + 5] = (coeffs[i + 3] >> 1) as u8;
            packed[idx + 6] = ((coeffs[i + 3] >> 9) | (coeffs[i + 4] << 4)) as u8;
            packed[idx + 7] = (coeffs[i + 4] >> 4) as u8;
            packed[idx + 8] = ((coeffs[i + 4] >> 12) | (coeffs[i + 5] << 1)) as u8;
            packed[idx + 9] = ((coeffs[i + 5] >> 7) | (coeffs[i + 6] << 6)) as u8;
            packed[idx + 10] = (coeffs[i + 6] >> 2) as u8;
            packed[idx + 11] = ((coeffs[i + 6] >> 10) | (coeffs[i + 7] << 3)) as u8;
            packed[idx + 12] = (coeffs[i + 7] >> 5) as u8;
        }
        
        Ok(packed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand::rngs::StdRng;
    
    #[derive(Clone)]
    struct TestModulus;
    impl Modulus for TestModulus {
        const Q: u32 = 3329;
        const N: usize = 256;
    }
    
    #[test]
    fn test_pack_unpack_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        
        // Test various bit widths
        for bits in [10, 12, 13, 23] {
            let mask = (1u32 << bits) - 1;
            
            // Create random polynomial with coefficients fitting in `bits` bits
            let mut poly = Polynomial::<TestModulus>::zero();
            for i in 0..TestModulus::N {
                poly.coeffs[i] = rng.gen::<u32>() & mask;
            }
            
            // Pack and unpack
            let packed = DefaultCoefficientSerde::pack_coeffs(&poly, bits).unwrap();
            let unpacked = <DefaultCoefficientSerde as CoefficientUnpacker<TestModulus>>::unpack_coeffs(&packed, bits).unwrap();
            
            // Verify roundtrip
            for i in 0..TestModulus::N {
                assert_eq!(poly.coeffs[i], unpacked.coeffs[i], 
                          "Mismatch at index {} for {} bits", i, bits);
            }
        }
    }
    
    #[test]
    fn test_bytes_required() {
        assert_eq!(bytes_required(10, 256), 320);  // Kyber ciphertext
        assert_eq!(bytes_required(12, 256), 384);  // Kyber public key
        assert_eq!(bytes_required(13, 256), 416);  // Dilithium
        assert_eq!(bytes_required(23, 256), 736);  // Dilithium signature
    }
    
    #[test]
    fn test_optimized_10bit() {
        let mut rng = StdRng::seed_from_u64(42);
        
        // Create random polynomial with 10-bit coefficients
        let mut poly = Polynomial::<TestModulus>::zero();
        for i in 0..TestModulus::N {
            poly.coeffs[i] = rng.gen::<u32>() & 0x3FF;
        }
        
        // Test optimized packing
        let packed_opt = DefaultCoefficientSerde::pack_10bit(&poly).unwrap();
        let packed_gen = DefaultCoefficientSerde::pack_coeffs(&poly, 10).unwrap();
        assert_eq!(packed_opt, packed_gen);
        
        // Test optimized unpacking
        let unpacked_opt = DefaultCoefficientSerde::unpack_10bit::<TestModulus>(&packed_opt).unwrap();
        let unpacked_gen = <DefaultCoefficientSerde as CoefficientUnpacker<TestModulus>>::unpack_coeffs(&packed_gen, 10).unwrap();
        
        for i in 0..TestModulus::N {
            assert_eq!(unpacked_opt.coeffs[i], unpacked_gen.coeffs[i]);
            assert_eq!(unpacked_opt.coeffs[i], poly.coeffs[i]);
        }
    }
    
    #[test]
    fn test_invalid_parameters() {
        let poly = Polynomial::<TestModulus>::zero();
        
        // Test invalid bits_per_coeff
        assert!(DefaultCoefficientSerde::pack_coeffs(&poly, 0).is_err());
        assert!(DefaultCoefficientSerde::pack_coeffs(&poly, 33).is_err());
        
        // Test invalid unpacking length
        let short_bytes = vec![0u8; 10];
        assert!(<DefaultCoefficientSerde as CoefficientUnpacker<TestModulus>>::unpack_coeffs(&short_bytes, 10).is_err());
    }
}