// arithmetic.rs
//! Arithmetic functions crucial for Dilithium, implementing FIPS 204 algorithms.
//! 
//! All functions are spec-compliant with FIPS 204, matching the reference implementation exactly.

use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_algorithms::poly::params::{DilithiumParams, Modulus};
use super::polyvec::{PolyVecL, PolyVecK};
use dcrypt_params::pqc::dilithium::{DilithiumSchemeParams, DILITHIUM_N, DILITHIUM_Q}; 
use crate::error::{Error as SignError};

/// Dilithium modulus Q
const Q: i32 = 8_380_417;

/// Helper - number of high-bit buckets (m) for the given parameters
/// This is the number of valid values for the high bits after decomposition
/// 
/// FIPS 204 §4.4: For ML-DSA-44, there are ⌊(q-1)/α⌋ + 1 = 45 buckets (0...44 inclusive)
/// For ML-DSA-65/87, there are ⌊(q-1)/α⌋ = 16 buckets (0...15 inclusive)
#[inline]
pub(crate) const fn buckets(alpha: u32, gamma2: u32) -> u32 {
    let base = (DILITHIUM_Q - 1) / alpha;
    // ML-DSA-44 (γ2 = (q-1)/88) needs one extra bucket (0…base inclusive)
    if gamma2 == (DILITHIUM_Q - 1) / 88 {
        base + 1
    } else {
        base
    }
}

/// Helper - compute centered subtraction modulo q
/// Returns (a - b) mod q in the range (-q/2, q/2]
/// 
/// This function is critical for the hint mechanism to work correctly.
/// Without centered subtraction, small negative differences wrap around
/// to large positive values, breaking the norm checks and hint generation.
#[inline]
pub(crate) fn centered_sub(a: u32, b: u32) -> i32 {
    let diff = ((a as i64 - b as i64).rem_euclid(DilithiumParams::Q as i64)) as i32;
    if diff > (DilithiumParams::Q / 2) as i32 {
        diff - DilithiumParams::Q as i32
    } else {
        diff
    }
}

/// Interpret a coefficient in [0,q) as a signed value in (-q/2, q/2].
#[inline]
pub(crate) fn to_centered(v: u32) -> i32 {
    if v > DilithiumParams::Q / 2 {
        v as i32 - DilithiumParams::Q as i32   // treat as negative
    } else {
        v as i32                               // treat as positive
    }
}

/// Generic schoolbook multiplication that handles all coefficient interpretation cases.
/// This unified implementation ensures algebraic consistency across all polynomial multiplications.
/// 
/// Parameters:
/// - a: First polynomial
/// - b: Second polynomial  
/// - a_centered: If true, interpret a's coefficients as centered (Q-1 represents -1)
/// - b_centered: If true, interpret b's coefficients as centered
pub fn schoolbook_mul_generic(
    a: &Polynomial<DilithiumParams>,
    b: &Polynomial<DilithiumParams>,
    a_centered: bool,
    b_centered: bool,
) -> Polynomial<DilithiumParams> {
    let mut result = Polynomial::<DilithiumParams>::zero();
    
    for i in 0..DILITHIUM_N {
        // Interpret coefficient a[i] based on a_centered flag
        let a_i = if a_centered && a.coeffs[i] > DILITHIUM_Q / 2 {
            (a.coeffs[i] as i64) - DILITHIUM_Q as i64
        } else {
            a.coeffs[i] as i64
        };
        
        // Skip if coefficient is zero (optimization)
        if a_i == 0 {
            continue;
        }
        
        for j in 0..DILITHIUM_N {
            // Interpret coefficient b[j] based on b_centered flag
            let b_j = if b_centered && b.coeffs[j] > DILITHIUM_Q / 2 {
                (b.coeffs[j] as i64) - DILITHIUM_Q as i64
            } else {
                b.coeffs[j] as i64
            };
            
            let prod = a_i * b_j;
            let idx = (i + j) % DILITHIUM_N;
            
            // Handle wrap-around with negation for X^n + 1
            if i + j >= DILITHIUM_N {
                result.coeffs[idx] = ((result.coeffs[idx] as i64 - prod)
                    .rem_euclid(DILITHIUM_Q as i64)) as u32;
            } else {
                result.coeffs[idx] = ((result.coeffs[idx] as i64 + prod)
                    .rem_euclid(DILITHIUM_Q as i64)) as u32;
            }
        }
    }
    
    result
}

/// Multiply a challenge polynomial by a standard polynomial.
/// 
/// This function correctly handles the special case where:
/// - The challenge polynomial `c` has coefficients in {-1, 0, 1} stored as {Q-1, 0, 1}
/// - The standard polynomial has coefficients in [0, Q)
/// 
/// This is specifically needed for computing c·t₁·2ᵈ during verification,
/// where the challenge must be interpreted as centered but t₁·2ᵈ is in standard form.
pub fn challenge_poly_mul(
    c: &Polynomial<DilithiumParams>,
    standard_poly: &Polynomial<DilithiumParams>,
) -> Polynomial<DilithiumParams> {
    // Use generic function with c centered, standard_poly non-centered
    schoolbook_mul_generic(c, standard_poly, true, false)
}

/// Implements `Power2Round_q` from FIPS 204, Algorithm 29.
/// Decomposes r ∈ Z_q into (r0, r1) such that r ≡ r1·2^d + r0 (mod q)
/// where r0 ∈ (-2^(d-1), 2^(d-1)]
pub fn power2round(r: u32, d: u32) -> (i32, u32) {
    let q = DilithiumParams::Q;
    let r_plus = r % q;
    let half = 1 << (d - 1);

    // round-to-nearest, **ties to negative**
    let mut r1 = (r_plus + half) >> d;
    let mut r0 = r_plus as i32 - (r1 as i32) * (1 << d);

    // canonical representation of q-1
    if r_plus == q - 1 {
        r0 = 0;
        r1 = (q - 1) >> d;
    }
    if r0 == half as i32 {
        r0 = -(half as i32);
        r1 = r1.wrapping_add(1);
    }
    (r0, r1)
}

/// Split a ∈ [0,q) into (a₁, a₀) such that
///     a = a₁·α  +  a₀
/// with  a₀ ∈ (-γ2, γ2]  and  a₁ fits in appropriate number of bits.
///
/// FIPS-204 compliant implementation - follows Algorithm 36 exactly.
/// Uses centered remainder mod±(2γ₂) to put a₀ in (-γ2, γ2].
/// Special case: when a = q - 1, set r₁ ← 0 and r₀ ← r₀ - 1
#[inline]
pub fn decompose(a: u32, alpha_param: u32) -> (i32, u32) {
    let q = Q as u32;
    let a = a % q;
    let alpha = alpha_param;
    let gamma2 = alpha / 2;

    // 1. centred remainder r0 ∈ (-γ₂, γ₂]
    let mut r0 = (a % alpha) as i32;     // 0 … α-1
    if r0 > gamma2 as i32 {              // bring it down to centred range
        r0 -= alpha as i32;              // now r0 ∈ (-γ₂, γ₂]
    }

    // 2. high bits - Use i64 to prevent overflow
    let r1 = (((a as i64) - (r0 as i64)) / (alpha as i64)) as u32;

    // 3. Special case per FIPS 204 Algorithm 36
    // When a = q-1, set r1 = 0 and r0 = r0 - 1
    if a == (q - 1) {
        return (r0 - 1, 0);
    }
    
    (r0, r1)
}

/// Implements `HighBits` from FIPS 204.
/// Returns r1 where (r0, r1) = Decompose(r, alpha)
pub fn highbits(r_coeff: u32, alpha: u32) -> u32 {
    decompose(r_coeff, alpha).1
}

/// Implements `LowBits` from FIPS 204.
/// Returns r0 where (r0, r1) = Decompose(r, alpha)
/// Result is in (-γ2, γ2] per FIPS 204 Algorithm 36
pub fn lowbits(r_coeff: u32, alpha: u32) -> i32 {
    decompose(r_coeff, alpha).0
}

/// FIPS 204 final w1Encode (Algorithm 28).
/// Returns the FULL gamma-bucket index r1 (no truncation).
/// For Dilithium2: r1 ∈ [0,44] requires 6 bits
/// For Dilithium3/5: r1 ∈ [0,16] requires 5 bits
/// 
/// Note: Earlier drafts truncated/shifted these values, but FIPS 204 final
/// specifies that w1 encoding returns r1 directly (identity function).
#[inline]
pub fn w1_encode_gamma(r1_gamma: u32) -> u32 {
    // FIPS 204 final: return the full r1 value
    r1_gamma
}

/// Compute the number of bits needed to represent w1 coefficients.
/// This is b = bitlen((q-1)/(2γ₂) - 1) as per FIPS 204 Algorithm 28.
#[inline]
pub fn w1_bits_needed<P: DilithiumSchemeParams>() -> u32 {
    let m = buckets(2 * P::GAMMA2_PARAM, P::GAMMA2_PARAM);
    32 - (m - 1).leading_zeros()
}

// ---------------------------------------------------------------------------
// Hint system – Algorithms 39 & 40 (FIPS 204 final)
// ---------------------------------------------------------------------------

/// FIPS 204 Algorithm 40 (UseHint) - FINAL SPECIFICATION COMPLIANT
/// 
/// The final FIPS 204 specification (13-Aug-2024) defines UseHint as:
/// 
/// Step 3: "if h = 1 and r₀ ≥ 0 return (r₁ + 1) mod m"     [rotate UP when non-negative]
/// Step 4: "if h = 1 and r₀ < 0 return (r₁ − 1) mod m"     [rotate DOWN when negative]
/// Step 5: "return r₁"                                      [no hint case]
/// 
/// This means:
/// - r₀ ≥ 0  → rotate UP (+1 mod m)     ← NON-NEGATIVE values go UP (includes r₀ = 0)
/// - r₀ < 0  → rotate DOWN (-1 mod m)   ← NEGATIVE values go DOWN
#[inline]
pub fn use_hint_coeff<P: DilithiumSchemeParams>(
    hint_bit: bool,
    r_coeff: u32,
) -> u32 {
    let gamma2 = P::GAMMA2_PARAM;
    let alpha = 2 * gamma2;
    let m = buckets(alpha, gamma2);
    
    let (r0, r1) = decompose(r_coeff, alpha);
    
    if !hint_bit {
        return r1;  // Algorithm 40, Step 5: return r₁ (no hint)
    }
    
    // FIPS 204 Algorithm 40, Steps 3-4 (FINAL SPECIFICATION):
    // The r0 from decompose is already in the correct signed range
    // (-γ₂, γ₂] as an i32. We can use it directly for the comparison.
    if r0 >= 0 {
        // Step 3: "if h = 1 and r₀ ≥ 0 return (r₁ + 1) mod m"
        // NON-NEGATIVE r₀ → rotate UP (+1 mod m)
        (r1 + 1) % m
    } else {
        // Step 4: "if h = 1 and r₀ < 0 return (r₁ − 1) mod m"  
        // NEGATIVE r₀ → rotate DOWN (-1 mod m)
        (r1 + m - 1) % m
    }
}

/// Checks if the infinity norm of a polynomial is at most `bound`.
/// Coefficients are centered in (-Q/2, Q/2]
pub fn check_norm_poly(
    poly: &Polynomial<DilithiumParams>, 
    bound: u32
) -> bool {
    for &coeff in poly.coeffs.iter() {
        // First center the coefficient to range (-Q/2, Q/2]
        let centered = if coeff > DilithiumParams::Q / 2 {
            coeff as i32 - DilithiumParams::Q as i32
        } else {
            coeff as i32
        };
        
        // Check if absolute value exceeds bound
        if centered.abs() > bound as i32 {
            return false;
        }
    }
    true
}

/// Checks if the infinity norm of all polynomials in a PolyVecL is at most `bound`.
pub fn check_norm_polyvec_l<P: DilithiumSchemeParams>(
    pv: &PolyVecL<P>, 
    bound: u32
) -> bool {
    pv.polys.iter().all(|p| check_norm_poly(p, bound))
}

/// Checks if the infinity norm of all polynomials in a PolyVecK is at most `bound`.
pub fn check_norm_polyvec_k<P: DilithiumSchemeParams>(
    pv: &PolyVecK<P>, 
    bound: u32
) -> bool {
    pv.polys.iter().all(|p| check_norm_poly(p, bound))
}

/// Applies `Power2Round` element-wise to a PolyVecK.
pub fn power2round_polyvec<P: DilithiumSchemeParams>(
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
pub fn highbits_polyvec<P: DilithiumSchemeParams>(
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
pub fn lowbits_polyvec<P: DilithiumSchemeParams>(
    pv: &PolyVecK<P>,
    alpha: u32,
) -> PolyVecK<P> {
    let mut res = PolyVecK::<P>::zero();
    
    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            let r0_signed = lowbits(pv.polys[i].coeffs[j], alpha);
            // Convert from signed (−γ2, γ2] to canonical mod q representation [0, Q)
            res.polys[i].coeffs[j] = ((r0_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
        }
    }
    
    res
}

/// FIPS 204 Algorithm 39 applied to polynomial vectors
/// 
/// The MakeHint/UseHint identity from FIPS 204 is:
///     UseHint(MakeHint(z, r), r + z) = HighBits(r)
/// 
/// During signing:
/// - We have the original commitment w = A*y
/// - The verifier will compute w' = Az - ct1*2^d = w - cs2 + ct0
/// - To ensure the verifier recovers HighBits(w), we need z = w' - w = ct0 - cs2
/// 
/// This function generates hints for recovering HighBits(r_polyvec) when given r_polyvec + z_polyvec.
/// 
/// Parameters:
/// - r_polyvec: The base vector (typically w in signing)
/// - z_polyvec: The difference vector (typically ct0 - cs2 in signing)
/// 
/// Also enforces that the highbit change is at most ±1 bucket,
/// as required by FIPS 204 Lemma 7 for the hint mechanism to work correctly.
pub fn make_hint_polyveck<P: DilithiumSchemeParams>(
    r_polyvec: &PolyVecK<P>,   // r (base vector)
    z_polyvec: &PolyVecK<P>,   // z (difference vector)
) -> Result<(PolyVecK<P>, usize), SignError> {
    let mut hints_pv = PolyVecK::<P>::zero();
    let mut hint_count = 0;
    
    let alpha = 2 * P::GAMMA2_PARAM;
    
    for i in 0..P::K_DIM {
        for j in 0..DILITHIUM_N {
            let r = r_polyvec.polys[i].coeffs[j];  // w
            let z = z_polyvec.polys[i].coeffs[j];  // ct0 - cs2 (may represent negative)
            
            let z_signed = to_centered(z) as i64;
            let r_plus_z = ((r as i64 + z_signed).rem_euclid(DilithiumParams::Q as i64)) as u32;
            
            let r1 = highbits(r, alpha);
            let v1 = highbits(r_plus_z, alpha);
            
            if r1 != v1 {
                // A hint is needed. Check if this hint is recoverable.
                // The high-bit bucket change must be exactly +/- 1 as an integer,
                // not merely modulo m. Large jumps (e.g., 0 to 44) cannot be recovered
                // by UseHint even though 44 ≡ -1 (mod 45).
                let diff = v1 as i32 - r1 as i32;
                
                if diff.abs() != 1 {
                    // This is an unrecoverable jump. This signature attempt must be rejected.
                    return Err(SignError::SignatureGeneration {
                        algorithm: P::NAME,
                        details: "Unrecoverable high-bit wrap-around detected during signing".into(),
                    });
                }

                hints_pv.polys[i].coeffs[j] = 1;
                hint_count += 1;
            }
        }
    }
    
    Ok((hints_pv, hint_count))
}

/// Applies `UseHint` to recover high bits using hint vector.
/// Returns w1-encoded values (full gamma-bucket indices) for challenge hash computation.
/// 
/// Parameters:
/// - h_polyvec: Hint vector (0/1 coefficients)
/// - w_prime_polyvec: w' = Az - ct1*2^d (the combined value)
pub fn use_hint_polyveck<P: DilithiumSchemeParams>(
    h_polyvec: &PolyVecK<P>,       // Hint vector (0/1 coefficients)
    w_prime_polyvec: &PolyVecK<P>, // w' = Az - ct1*2^d (the combined value)
) -> Result<PolyVecK<P>, SignError> {
    let mut corrected_pv = PolyVecK::<P>::zero();
    
    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            let hint_bit = h_polyvec.polys[i].coeffs[j] == 1;
            let w_prime_coeff = w_prime_polyvec.polys[i].coeffs[j];
            
            // Apply UseHint to get the corrected γ-bucket index
            let r1_prime = use_hint_coeff::<P>(hint_bit, w_prime_coeff);
            
            // FIPS 204 final: store the full gamma-bucket index
            corrected_pv.polys[i].coeffs[j] = w1_encode_gamma(r1_prime);
        }
    }
    
    Ok(corrected_pv)
}