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

/// Example: Dilithium parameter sets (basic, without NTT)
pub struct Dilithium2Params;

impl Modulus for Dilithium2Params {
    const Q: u32 = 8380417;  // 2^23 - 2^13 + 1
    const N: usize = 256;
}

/// Dilithium polynomial ring Rq = ℤq[X]/(Xᴺ + 1)
///
/// * Q = 2²³ – 2¹³ + 1 = 8,380,417 (prime)  
/// * N = 256 (⇒ ϕ = 512)  
/// * ζ = 1753 is a primitive 512-th root of unity mod Q  
///
/// All Montgomery-domain constants are derived for 32-bit words:
///   R       = 2³² mod Q                 = 4,193,792  
///   N_INV   = N⁻¹ · R mod Q            = 16,382  
///   Q_INV_NEG = –Q⁻¹ mod 2³²           = 0xFC7F_DFFF
pub struct DilithiumPolyModParams;

impl Modulus for DilithiumPolyModParams {
    const Q: u32 = 8_380_417;
    const N: usize = 256;
}

impl NttModulus for DilithiumPolyModParams {
    // ───── primitive root of unity (order 2·N) ─────
    const ZETA: u32 = 1_753;

    // We generate twiddles on-the-fly, so keep these empty
    const ZETAS: &'static [u32] = &[];
    const INV_ZETAS: &'static [u32] = &[];

    // ───── Montgomery/NTT helpers ─────
    /// (N⁻¹ · R) mod Q where R = 2³² mod Q
    const N_INV: u32 = 16_382;
    /// R = 2³² mod Q
    const MONT_R: u32 = 4_193_792;
    /// –Q⁻¹ mod 2³² (for Montgomery reduction)
    const Q_INV_NEG: u32 = 0xFC7F_DFFF;
}

/// Compile-time verification of Dilithium NTT parameters
#[allow(dead_code)]
const _: () = {
    // Helper for modular exponentiation (const context)
    const fn const_pow_mod(mut base: u32, mut exp: u32, modulus: u32) -> u32 {
        let mut result = 1u64;
        let m = modulus as u64;
        while exp > 0 {
            if exp & 1 == 1 {
                result = (result * (base as u64)) % m;
            }
            base = ((base as u64 * base as u64) % m) as u32;
            exp >>= 1;
        }
        result as u32
    }
    
    // Verify ζ^512 ≡ 1 (mod Q)
    const ZETA_512: u32 = const_pow_mod(DilithiumPolyModParams::ZETA, 512, DilithiumPolyModParams::Q);
    const _: () = assert!(ZETA_512 == 1);
    
    // Verify ζ^256 ≡ -1 (mod Q)
    const ZETA_256: u32 = const_pow_mod(DilithiumPolyModParams::ZETA, 256, DilithiumPolyModParams::Q);
    const _: () = assert!(ZETA_256 == DilithiumPolyModParams::Q - 1);
    
    // Verify R = 2^32 mod Q
    const R_CHECK: u64 = (1u64 << 32) % (DilithiumPolyModParams::Q as u64);
    const _: () = assert!(R_CHECK == DilithiumPolyModParams::MONT_R as u64);
    
    // Verify Q * Q_INV_NEG ≡ -1 (mod 2^32)
    const PROD: u64 = (DilithiumPolyModParams::Q as u64)
        .wrapping_mul(DilithiumPolyModParams::Q_INV_NEG as u64);
    const _: () = assert!((PROD & 0xFFFFFFFF) == 0xFFFFFFFF);
};

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
    fn test_dilithium_poly_mod_params() {
        assert_eq!(DilithiumPolyModParams::Q, 8_380_417);
        assert_eq!(DilithiumPolyModParams::N, 256);
        assert!(is_prime(DilithiumPolyModParams::Q));
        assert!(is_power_of_two(DilithiumPolyModParams::N));
        
        // Verify NTT parameters
        assert_eq!(DilithiumPolyModParams::ZETA, 1_753);
        assert_eq!(DilithiumPolyModParams::MONT_R, 4_193_792);
        assert_eq!(DilithiumPolyModParams::N_INV, 16_382);
        assert_eq!(DilithiumPolyModParams::Q_INV_NEG, 0xFC7F_DFFF);
    }
}