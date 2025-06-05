//! params.rs - Enhanced polynomial ring parameters with NTT support

#![cfg_attr(not(feature = "std"), no_std)]

/// Basic trait defining the modulus and degree for a polynomial ring
pub trait Modulus {
    /// The primary modulus Q for coefficient arithmetic
    const Q: u32;
    
    /// The polynomial degree N (number of coefficients)
    const N: usize;
}

/// Extended trait for NTT-enabled moduli
pub trait NttModulus: Modulus {
    /// Primitive root of unity (generator)
    const ZETA: u32;
    
    /// Precomputed twiddle factors for forward NTT
    const ZETAS: &'static [u32];
    
    /// Precomputed twiddle factors for inverse NTT
    const INV_ZETAS: &'static [u32];
    
    /// N^-1 mod Q for final scaling in inverse NTT
    const N_INV: u32;
    
    /// Montgomery parameter R = 2^k mod Q
    const MONT_R: u32;
    
    /// -Q^-1 mod 2^32 for Montgomery reduction
    const Q_INV_NEG: u32;
}

/// Example: Kyber-256 parameter set
#[derive(Clone, Debug)]
pub struct Kyber256Params;

impl Modulus for Kyber256Params {
    const Q: u32 = 3329;
    const N: usize = 256;
}

impl NttModulus for Kyber256Params {
    const ZETA: u32 = 17;  // primitive 512-th root of unity mod 3329
    // Pre-computed tables dropped; Cooley-Tukey now derives twiddles on demand
    const ZETAS: &'static [u32] = &[];
    const INV_ZETAS: &'static [u32] = &[];
    /// (256⁻¹) in Montgomery form: (256⁻¹ · R₃₂) mod Q
    const N_INV: u32 = 2385;
    /// 2³² mod Q
    const MONT_R: u32 = 1353;
    /// -Q⁻¹ mod 2³² (0x94570CFF)
    const Q_INV_NEG: u32 = 0x94570CFF;
}

/// Example: Dilithium parameter sets
#[derive(Clone, Debug)]
pub struct Dilithium2Params;

impl Modulus for Dilithium2Params {
    const Q: u32 = 8380417;  // 2^23 - 2^13 + 1
    const N: usize = 256;
}

// Note: Dilithium NTT parameters would be added similarly

/// General Dilithium parameter set used by the signature implementation
#[derive(Clone, Debug)]
pub struct DilithiumParams;

impl Modulus for DilithiumParams {
    const Q: u32 = 8380417;  // 2^23 - 2^13 + 1
    const N: usize = 256;
}

impl NttModulus for DilithiumParams {
    const ZETA: u32 = 1753;  // primitive 512-th root of unity mod Q
    const ZETAS: &'static [u32] = &[];  // Using on-the-fly generation
    const INV_ZETAS: &'static [u32] = &[];
    const N_INV: u32 = 8347681;  // 256^-1 mod Q
    const MONT_R: u32 = 4193792;  // 2^32 mod Q  
    const Q_INV_NEG: u32 = 0x89E7F77F;  // -Q^-1 mod 2^32
}

/// Helper functions for parameter validation

/// Check if a number is prime (simplified check)
pub fn is_prime(q: u32) -> bool {
    if q < 2 {
        return false;
    }
    if q == 2 {
        return true;
    }
    if q % 2 == 0 {
        return false;
    }
    
    let sqrt_q = (q as f64).sqrt() as u32;
    for i in (3..=sqrt_q).step_by(2) {
        if q % i == 0 {
            return false;
        }
    }
    true
}

/// Check if N is a power of 2
pub fn is_power_of_two(n: usize) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kyber_params() {
        assert_eq!(Kyber256Params::Q, 3329);
        assert_eq!(Kyber256Params::N, 256);
        assert!(is_prime(Kyber256Params::Q));
        assert!(is_power_of_two(Kyber256Params::N));
    }
    
    #[test]
    fn test_dilithium_params() {
        assert_eq!(Dilithium2Params::Q, 8380417);
        assert_eq!(Dilithium2Params::N, 256);
        assert!(is_prime(Dilithium2Params::Q));
    }
    
    #[test]
    fn test_dilithium_general_params() {
        assert_eq!(DilithiumParams::Q, 8380417);
        assert_eq!(DilithiumParams::N, 256);
        assert!(is_prime(DilithiumParams::Q));
        assert!(is_power_of_two(DilithiumParams::N));
    }
}