//! Arithmetic functions crucial for Dilithium, implementing FIPS 203 algorithms.

use algorithms::poly::polynomial::Polynomial;
use algorithms::poly::params::{DilithiumParams, Modulus};
use super::polyvec::{PolyVecL, PolyVecK};
use params::pqc::dilithium::DilithiumParams as DilithiumSignParams;
use crate::error::{Error as SignError};

/// Implements `Power2Round_q` from FIPS 203, Algorithm 4.
/// Decomposes r ∈ Z_q into (r0, r1) such that r = r1·2^d + r0
/// where r0 ∈ (-2^(d-1), 2^(d-1)]
pub fn power2round(r_coeff: u32, d_param: u32) -> (i32, u32) {
    let r_signed = r_coeff as i32;
    let power_d_minus_1 = 1i32 << (d_param - 1);
    
    // r1 = ⌊(r + 2^(d-1) - 1) / 2^d⌋
    let r1_signed = (r_signed + power_d_minus_1 - 1) >> d_param;
    
    // r0 = r - r1·2^d
    let r0_signed = r_signed - (r1_signed << d_param);
    
    (r0_signed, r1_signed as u32)
}

/// Implements `Decompose_alpha` from FIPS 203, Algorithm 5.
/// Decomposes r ∈ Z_q into (r0, r1) such that r = r1·α + r0
/// where r0 ∈ (-α/2, α/2] and α is even
pub fn decompose(r_coeff: u32, alpha: u32) -> (i32, u32) {
    debug_assert!(alpha > 0 && alpha % 2 == 0, "alpha must be positive and even");
    
    let r_signed = r_coeff as i32;
    let alpha_signed = alpha as i32;
    let alpha_half = alpha_signed / 2;
    
    // Step 1: r0 = r mod α (centered)
    let mut r0 = r_signed % alpha_signed;
    if r0 < 0 {
        r0 += alpha_signed;
    }
    
    // Step 2: If r0 > α/2, then r0 ← r0 - α
    if r0 > alpha_half {
        r0 -= alpha_signed;
    }
    
    // Step 3: r1 = (r - r0) / α
    let r1 = ((r_signed - r0) / alpha_signed) as u32;
    
    // Step 4: If r0 = -α/2, then r0 ← α/2 and r1 ← r1 - 1
    if r0 == -alpha_half {
        r0 = alpha_half;
        return (r0, r1.wrapping_sub(1));
    }
    
    (r0, r1)
}

/// Implements `HighBits` from FIPS 203.
/// Returns r1 where (r0, r1) = Decompose(r, alpha)
pub fn highbits(r_coeff: u32, alpha: u32) -> u32 {
    decompose(r_coeff, alpha).1
}

/// Implements `LowBits` from FIPS 203.
/// Returns r0 where (r0, r1) = Decompose(r, alpha)
pub fn lowbits(r_coeff: u32, alpha: u32) -> i32 {
    decompose(r_coeff, alpha).0
}

/// Implements `MakeHint_gamma2` from FIPS 203, Algorithm 6.
/// Returns 1 if high bits of (v0, v1) need adjustment, 0 otherwise
pub fn make_hint_coeff(v0_coeff: i32, _v1_coeff: u32, gamma2: u32) -> bool {
    let gamma2_signed = gamma2 as i32;
    v0_coeff != 0 && v0_coeff != gamma2_signed && v0_coeff != -gamma2_signed
}

/// Implements `UseHint_gamma2` from FIPS 203, Algorithm 7.
/// Corrects high bits r1 using hint bit
pub fn use_hint_coeff(hint_bit: bool, r_coeff: u32, gamma2: u32) -> u32 {
    let (r0_signed, mut r1) = decompose(r_coeff, 2 * gamma2);
    
    if hint_bit {
        if r0_signed > 0 {
            // r1' = (r1 + 1) mod m where m = ⌊(q-1)/(2γ2)⌋ + 1
            // For Dilithium parameters, this wrapping is implicit
            r1 = r1.wrapping_add(1);
        } else if r0_signed < 0 {
            r1 = r1.wrapping_sub(1);
        }
        // If r0 == 0, hint should be 0, so this branch shouldn't execute
    }
    
    r1
}

/// Checks if the infinity norm of a polynomial is at most `bound`.
/// Coefficients are centered in (-Q/2, Q/2]
pub fn check_norm_poly<P: DilithiumSignParams>(
    poly: &Polynomial<DilithiumParams>, 
    bound: u32
) -> bool {
    let q_half = (DilithiumParams::Q / 2) as i32;
    
    for &coeff in poly.coeffs.iter() {
        let mut centered_coeff = coeff as i32;
        // Center coefficient
        if centered_coeff > q_half {
            centered_coeff -= DilithiumParams::Q as i32;
        }
        if centered_coeff.abs() > bound as i32 {
            return false;
        }
    }
    true
}

/// Checks if the infinity norm of all polynomials in a PolyVecL is at most `bound`.
pub fn check_norm_polyvec_l<P: DilithiumSignParams>(
    pv: &PolyVecL<P>, 
    bound: u32
) -> bool {
    pv.polys.iter().all(|p| check_norm_poly::<P>(p, bound))
}

/// Checks if the infinity norm of all polynomials in a PolyVecK is at most `bound`.
pub fn check_norm_polyvec_k<P: DilithiumSignParams>(
    pv: &PolyVecK<P>, 
    bound: u32
) -> bool {
    pv.polys.iter().all(|p| check_norm_poly::<P>(p, bound))
}

/// Applies `Power2Round` element-wise to a PolyVecK.
pub fn power2round_polyvec<P: DilithiumSignParams>(
    pv: &PolyVecK<P>,
    d_param: u32,
) -> (PolyVecK<P>, PolyVecK<P>) {
    let mut pv0 = PolyVecK::<P>::zero();
    let mut pv1 = PolyVecK::<P>::zero();
    
    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            let (r0_signed, r1) = power2round(pv.polys[i].coeffs[j], d_param);
            // Store r0 as positive representative in [0, Q-1]
            pv0.polys[i].coeffs[j] = ((r0_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
            pv1.polys[i].coeffs[j] = r1;
        }
    }
    
    (pv0, pv1)
}

/// Applies `HighBits` element-wise to a PolyVecK.
pub fn highbits_polyvec<P: DilithiumSignParams>(
    pv: &PolyVecK<P>,
    alpha: u32,
) -> PolyVecK<P> {
    let mut res = PolyVecK::<P>::zero();
    
    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            res.polys[i].coeffs[j] = highbits(pv.polys[i].coeffs[j], alpha);
        }
    }
    
    res
}

/// Applies `LowBits` element-wise to a PolyVecK.
pub fn lowbits_polyvec<P: DilithiumSignParams>(
    pv: &PolyVecK<P>,
    alpha: u32,
) -> PolyVecK<P> {
    let mut res = PolyVecK::<P>::zero();
    
    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            let r0_signed = lowbits(pv.polys[i].coeffs[j], alpha);
            // Store as positive representative
            res.polys[i].coeffs[j] = ((r0_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
        }
    }
    
    res
}

/// Applies `MakeHint` to create hint vector h for signature compression.
/// Takes v = w - cs2 - ct0 and creates hints for UseHint.
pub fn make_hint_polyveck<P: DilithiumSignParams>(
    v_polyvec: &PolyVecK<P>, // v = w - cs2 - ct0
) -> Result<(PolyVecK<P>, usize), SignError> {
    let mut hints_pv = PolyVecK::<P>::zero();
    let mut hint_count = 0;
    
    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            let v_coeff = v_polyvec.polys[i].coeffs[j];
            let (v0, v1) = decompose(v_coeff, 2 * P::GAMMA2_PARAM);
            
            if make_hint_coeff(v0, v1, P::GAMMA2_PARAM) {
                hints_pv.polys[i].coeffs[j] = 1;
                hint_count += 1;
            } else {
                hints_pv.polys[i].coeffs[j] = 0;
            }
        }
    }
    
    Ok((hints_pv, hint_count))
}

/// Applies `UseHint` to recover high bits using hint vector.
pub fn use_hint_polyveck<P: DilithiumSignParams>(
    h_polyvec: &PolyVecK<P>, // Hint vector (0/1 coefficients)
    r_polyvec: &PolyVecK<P>, // w' = Az - ct1
) -> Result<PolyVecK<P>, SignError> {
    let mut corrected_pv = PolyVecK::<P>::zero();
    
    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            let hint_bit = h_polyvec.polys[i].coeffs[j] == 1;
            let r_coeff = r_polyvec.polys[i].coeffs[j];
            corrected_pv.polys[i].coeffs[j] = use_hint_coeff(hint_bit, r_coeff, P::GAMMA2_PARAM);
        }
    }
    
    Ok(corrected_pv)
}