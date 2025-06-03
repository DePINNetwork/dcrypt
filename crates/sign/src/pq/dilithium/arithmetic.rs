// File: crates/sign/src/pq/dilithium/arithmetic.rs
//! Arithmetic functions crucial for Dilithium, such as decomposition into
//! high and low bits (`Power2Round`, `Decompose`), hint generation and usage
//! (`MakeHint`, `UseHint`), and coefficient norm checking (`CheckNorm`).
//! These functions operate on individual coefficients or polynomials.

use algorithms::poly::polynomial::Polynomial;
use super::polyvec::{DilithiumPolyModParams, PolyVec};
use params::pqc::dilithium::{DilithiumParams, DILITHIUM_Q};

/// Implements `Power2Round_q` from FIPS 203 (Dilithium spec), Algorithm 4.
/// Decomposes a coefficient `r_coeff` (in `Z_q`) into `(r0, r1)` such that
/// `r_coeff = r1 * 2^d + r0`, where `r0` is in `(-2^(d-1), 2^(d-1)]`.
///
/// # Arguments
/// * `r_coeff`: A polynomial coefficient, $0 \le r\_coeff < Q$.
/// * `d_param`: The bit-dropping parameter `d` (e.g., `P::D_PARAM`).
///
/// # Returns
/// A tuple `(r0, r1)`:
///   - `r0`: The low-order part, as a signed `i32` in the range `(-2^(d-1), 2^(d-1)]`.
///   - `r1`: The high-order part, as a `u32`.
pub fn power2round(r_coeff: u32, d_param: u32) -> (i32, u32) {
    let r_signed = r_coeff as i32;
    let power_of_d_minus_1 = 1i32 << (d_param - 1);

    // r1 = round(r_coeff / 2^d)
    // Equivalent to (r_coeff + 2^(d-1) - epsilon_for_tie_breaking) / 2^d
    // FIPS 203 uses (r + 2^(d-1) - 1) / 2^d (integer division)
    // which is ((r_signed + power_of_d_minus_1 -1) >> d_param) if d_param > 0
    let r1_signed = if d_param > 0 {
        (r_signed + power_of_d_minus_1 - 1).wrapping_shr(d_param)
    } else {
        r_signed // if d=0, 2^d = 1, r1 = r
    };

    let r0_signed = r_signed - (r1_signed << d_param);
    (r0_signed, r1_signed as u32)
}

/// Implements `Decompose_alpha` from FIPS 203, Algorithm 5.
/// Decomposes a coefficient `r_coeff` (in `Z_q`) into `(r0, r1)` such that
/// `r_coeff = r1 * alpha + r0`, where `r0` is in `(-alpha/2, alpha/2]`.
/// The parameter `alpha` must be an even integer. In Dilithium, `alpha = 2 * gamma2`.
///
/// # Arguments
/// * `r_coeff`: A polynomial coefficient, $0 \le r\_coeff < Q$.
/// * `alpha`: The decomposition modulus (e.g., `2 * P::GAMMA2_PARAM`).
///
/// # Returns
/// A tuple `(r0, r1)`:
///   - `r0`: The low-order part, as a signed `i32` in `(-alpha/2, alpha/2]`.
///   - `r1`: The high-order part, as a `u32`.
pub fn decompose(r_coeff: u32, alpha: u32) -> (i32, u32) {
    debug_assert!(alpha > 0 && alpha % 2 == 0, "alpha must be positive and even for Decompose");
    let mut r0_signed = r_coeff as i32 % alpha as i32; // r mod alpha, result in [0, alpha-1] or [-(alpha-1), 0]
                                                     // Make it positive in [0, alpha-1]
    if r0_signed < 0 { r0_signed += alpha as i32; }

    let alpha_half = (alpha / 2) as i32;
    if r0_signed > alpha_half {
        r0_signed -= alpha as i32;
    }
    // At this point r0_signed is in [-alpha_half+1, alpha_half]
    // Spec needs (-alpha/2, alpha/2], so if r0 = -alpha/2, make it alpha/2
    // and adjust r1.
    // r1 = (r_coeff - r0_signed) / alpha
    // Using direct formula from FIPS 203:
    // r1 = floor( (r_coeff + alpha/2 - 1) / alpha ) if using integer division.
    // More simply from reference:
    // r0 = r mod+- alpha (centered remainder)
    // r1 = (r - r0) / alpha

    // Using spec's step-by-step:
    let r_signed = r_coeff as i32;
    let alpha_s = alpha as i32;
    let mut r0 = r_signed.rem_euclid(alpha_s); // r0 in [0, alpha-1)
    if r0 > alpha_s / 2 {
        r0 -= alpha_s;
    }
    let r1 = (r_signed - r0) / alpha_s;
    (r0, r1 as u32)
}


/// Implements `MakeHint_gamma2` from FIPS 203, Algorithm 6.
/// Determines if a hint bit is needed based on coefficients `v0_coeff` and `v1_coeff`.
/// Here, `v0_coeff` represents the low bits of `(w - c*s2 - c*t0)` and `v1_coeff` the high bits.
/// The hint is 1 iff `v0 != 0` AND `v0 != +-gamma2`.
///
/// # Arguments
/// * `v0_coeff`: The low-order coefficient (signed, centered) from `Decompose(v_k, 2*gamma2)`.
/// * `v1_coeff`: The high-order coefficient from `Decompose(v_k, 2*gamma2)`. (Not directly used by this check).
/// * `gamma2`: The `gamma2` parameter of the Dilithium scheme.
///
/// # Returns
/// `true` (hint=1) if conditions are met, `false` (hint=0) otherwise.
pub fn make_hint_coeff(v0_coeff: i32, _v1_coeff: u32, gamma2: u32) -> bool {
    v0_coeff != 0 && v0_coeff != (gamma2 as i32) && v0_coeff != -(gamma2 as i32)
}


/// Implements `UseHint_gamma2` from FIPS 203, Algorithm 7.
/// Corrects a high-bits coefficient `r1_coeff` using a hint bit.
/// `r_coeff` is a coefficient of `w1_prime = A*z - c*t1`.
///
/// # Arguments
/// * `hint_bit`: The hint bit (0 or 1).
/// * `r_coeff`: A coefficient of `w1_prime`.
/// * `gamma2`: The `gamma2` parameter.
///
/// # Returns
/// The corrected high-bits coefficient `r1_coeff`.
pub fn use_hint_coeff(hint_bit: bool, r_coeff: u32, gamma2: u32) -> u32 {
    let (r0_signed, r1) = decompose(r_coeff, 2 * gamma2);

    if hint_bit { // If hint is 1
        if r0_signed > 0 {
            // (r1 + 1) mod (Q / (2*gamma2))
            // Dilithium Q is 8380417. 2*gamma2 for L2/3 is (Q-1)/44.
            // Q / (2*gamma2) is not necessarily a power of 2.
            // The spec states r1 is in Z_{floor( (q-1) / (2*gamma2) ) + 1}
            // This function corrects r1 to be the high bits of r0 or r0+-gamma2.
            // If r0 > 0 and hint is 1, it means r0 was gamma2, so effectively r1 should be r1+1.
            // If r0 < 0 and hint is 1, it means r0 was -gamma2, so effectively r1 should be r1-1.
            // The modulo operation on r1 is implicit in the range it's sampled from/used.
            // For now, simple addition/subtraction.
            return r1.wrapping_add(1);
        } else if r0_signed < 0 { // r0_signed is not 0 because make_hint would be false
            return r1.wrapping_sub(1);
        }
        // if r0_signed == 0, hint should be 0, this branch not taken.
    }
    r1
}

/// Checks if the infinity norm of a polynomial `p` is less than or equal to `bound`.
/// Coefficients are treated as centered in `(-Q/2, Q/2]`.
pub fn check_norm_poly<P: DilithiumParams>(poly: &Polynomial<DilithiumPolyModParams>, bound: u32) -> bool {
    for &coeff in poly.coeffs.iter() {
        let mut centered_coeff = coeff as i32;
        // Center coefficient around 0: if coeff > Q/2, then centered_coeff = coeff - Q
        if centered_coeff > (DILITHIUM_Q / 2) as i32 {
            centered_coeff = centered_coeff.wrapping_sub(DILITHIUM_Q as i32);
        }
        if centered_coeff.abs() > bound as i32 {
            return false;
        }
    }
    true
}

/// Checks if the infinity norm of all polynomials in a PolyVec `pv` is less than or equal to `bound`.
pub fn check_norm_polyvec<P: DilithiumParams, const DIM: usize>(pv: &PolyVec<P, DIM>, bound: u32) -> bool {
    pv.polys.iter().all(|p| check_norm_poly::<P>(p, bound))
}

/// Applies `Power2Round` element-wise to a `PolyVec`.
/// Returns two `PolyVec`s: `(pv0, pv1)`.
pub fn power2round_polyvec<P: DilithiumParams, const DIM: usize>(
    pv: &PolyVec<P, DIM>,
    d_param: u32,
) -> (PolyVec<P, DIM>, PolyVec<P, DIM>) {
    let mut pv0_signed_coeffs = PolyVec::<P, DIM>::zero(); // Temporarily store signed r0
    let mut pv1 = PolyVec::<P, DIM>::zero();
    for i in 0..DIM {
        for j in 0..DILITHIUM_N {
            let (r0_signed, r1) = power2round(pv.polys[i].coeffs[j], d_param);
            // Store r0_signed as positive representative in [0, Q-1] for PolyVec
            pv0_signed_coeffs.polys[i].coeffs[j] = (r0_signed + DILITHIUM_Q as i32) as u32 % (DILITHIUM_Q as u32);
            pv1.polys[i].coeffs[j] = r1;
        }
    }
    (pv0_signed_coeffs, pv1)
}

/// Applies `HighBits` element-wise to a `PolyVec`.
/// `HighBits(r, alpha) = r1` where `(r0, r1) = Decompose(r, alpha)`.
pub fn highbits_polyvec<P: DilithiumParams, const DIM: usize>(
    pv: &PolyVec<P, DIM>,
    alpha: u32,
) -> PolyVec<P, DIM> {
    let mut res = PolyVec::<P, DIM>::zero();
    for i in 0..DIM {
        for j in 0..DILITHIUM_N {
            let (_, r1) = decompose(pv.polys[i].coeffs[j], alpha);
            res.polys[i].coeffs[j] = r1;
        }
    }
    res
}

/// Applies `LowBits` element-wise to a `PolyVec`.
/// `LowBits(r, alpha) = r0` where `(r0, r1) = Decompose(r, alpha)`.
/// `r0` is returned as its representative in `[0, Q-1]`.
pub fn lowbits_polyvec<P: DilithiumParams, const DIM: usize>(
    pv: &PolyVec<P, DIM>,
    alpha: u32,
) -> PolyVec<P, DIM> {
    let mut res = PolyVec::<P, DIM>::zero();
    for i in 0..DIM {
        for j in 0..DILITHIUM_N {
            let (r0_signed, _) = decompose(pv.polys[i].coeffs[j], alpha);
            res.polys[i].coeffs[j] = (r0_signed + DILITHIUM_Q as i32) as u32 % (DILITHIUM_Q as u32);
        }
    }
    res
}

/// Applies `MakeHint` element-wise to two `PolyVecK`.
/// `pv_v0` contains the low-bits components, `pv_v1` contains the high-bits components.
/// This function constructs the hint vector `h`.
///
/// TODO: This simplified version assumes `v0` and `v1` come from the same decomposition.
/// The actual `MakeHint` in Dilithium is more complex and depends on `(-c*t0)` and `(w - c*s2)`.
/// The hint `h_k` is 1 if `(w - c*s2 - c*t0)_k` is not recoverable without the hint.
/// For this skeleton, it acts as a placeholder.
pub fn make_hint_polyveck<P: DilithiumParams>(
    pv_v0: &PolyVecK<P>, // Represents the v0 part for hint decision
    pv_v1: &PolyVecK<P>, // Represents the v1 part for hint decision (not directly used by make_hint_coeff)
) -> Result<PolyVecK<P>, SignError> {
    let mut hints_pv = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM {
        for j in 0..DILITHIUM_N {
            let v0_c_signed = pv_v0.polys[i].coeffs[j] as i32; // Assuming it's already centered or correctly representing v0
            let v1_c = pv_v1.polys[i].coeffs[j];
            if make_hint_coeff(v0_c_signed, v1_c, P::GAMMA2_PARAM as u32) {
                hints_pv.polys[i].coeffs[j] = 1;
            } else {
                hints_pv.polys[i].coeffs[j] = 0;
            }
        }
    }
    Ok(hints_pv)
}

/// Applies `UseHint` element-wise to a `PolyVecK` based on a hint vector (also `PolyVecK`).
/// `pv_r` is the vector to be corrected (e.g., `w1_prime = A*z - c*t1`).
/// `pv_h` is the hint vector (polynomials with 0/1 coefficients).
///
/// TODO: The current `unpack_signature` for `h` is a placeholder.
/// A real implementation would unpack `h` into a structure that can be easily iterated
/// (e.g., a list of `OMEGA` indices where the hint is 1).
/// This function assumes `pv_h` is a PolyVecK where `polys[i].coeffs[j] = 1` if hint is set.
pub fn use_hint_polyveck_from_sig<P: DilithiumParams>(
    pv_h_from_sig: &PolyVecK<P>, // Hint vector unpacked from signature
    pv_r: &PolyVecK<P>,          // Polynomial vector to correct
) -> Result<PolyVecK<P>, SignError> {
    let mut corrected_pv = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM {
        for j in 0..DILITHIUM_N {
            let hint_bit = pv_h_from_sig.polys[i].coeffs[j] == 1;
            let r_coeff = pv_r.polys[i].coeffs[j];
            corrected_pv.polys[i].coeffs[j] = use_hint_coeff(hint_bit, r_coeff, P::GAMMA2_PARAM as u32);
        }
    }
    Ok(corrected_pv)
}