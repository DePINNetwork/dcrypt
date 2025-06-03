// File: crates/sign/src/pq/dilithium/sampling.rs
//! Sampling functions for Dilithium, including CBD for secrets/errors,
//! uniform bounded sampling for `y`, and sparse ternary sampling for challenge `c`.

use algorithms::poly::polynomial::Polynomial;
use super::polyvec::{DilithiumPolyModParams, PolyVec, PolyVecL, PolyVecK};
use params::pqc::dilithium::{DilithiumParams, DILITHIUM_N, DILITHIUM_Q};
// SHAKE128 for matrix A (in polyvec), SHAKE256 for errors, y, and challenge c sampling
use algorithms::xof::shake::ShakeXof256;
use algorithms::xof::ExtendableOutputFunction;
use algorithms::error::Result as AlgoResult;
use crate::error::{Error as SignError, Result as SignResult};

/// Samples a polynomial with coefficients from Centered Binomial Distribution CBD_eta.
/// Uses SHAKE256(seed || nonce) as the randomness source.
/// Each coefficient is $a-b$ where $a, b \leftarrow \sum_{i=0}^{\eta-1} \text{bit}_i$.
///
/// # Arguments
/// * `seed`: A 32-byte seed (typically `key_seed_for_s` from `keypair_internal`).
/// * `nonce`: A u8 nonce for domain separation (e.g., 0 for first poly in s1, 1 for second, etc.).
/// * `eta`: The CBD parameter (e.g., `P::ETA_S1S2`).
///
/// # Returns
/// A polynomial with coefficients in `[-eta, eta]`, represented in `[0, Q-1]`.
pub fn sample_poly_cbd_eta<P: DilithiumParams>(
    seed: &[u8; P::SEED_KEY_BYTES],
    nonce: u8,
    eta: u32,
) -> Result<Polynomial<DilithiumPolyModParams>, SignError> {
    if eta == 0 || eta > 4 { // Dilithium eta is typically 2 or 4
        return Err(SignError::Sampling(format!("Invalid eta for CBD: {}", eta)));
    }

    let mut xof = ShakeXof256::new();
    xof.update(seed).map_err(SignError::from_algo)?;
    xof.update(&[nonce]).map_err(SignError::from_algo)?;

    // Each coefficient requires 2*eta bits.
    // For eta=2, 4 bits per coeff. For eta=4, 8 bits (1 byte) per coeff.
    // Dilithium reference implementation samples 64*eta bits at a time for N/4 coefficients.
    // Let's sample bytes needed for all N coefficients.
    let bytes_needed = (DILITHIUM_N * 2 * eta as usize + 7) / 8;
    let mut buf = vec![0u8; bytes_needed];
    xof.squeeze(&mut buf).map_err(SignError::from_algo)?;

    let mut poly = Polynomial::<DilithiumPolyModParams>::zero();
    let mut bit_offset_in_buf = 0;

    for i in 0..DILITHIUM_N {
        let mut sum1 = 0i32;
        let mut sum2 = 0i32;
        for _ in 0..eta {
            sum1 += ((buf[bit_offset_in_buf / 8] >> (bit_offset_in_buf % 8)) & 1) as i32;
            bit_offset_in_buf += 1;
        }
        for _ in 0..eta {
            sum2 += ((buf[bit_offset_in_buf / 8] >> (bit_offset_in_buf % 8)) & 1) as i32;
            bit_offset_in_buf += 1;
        }
        let val_signed = sum1 - sum2; // In [-eta, eta]
        poly.coeffs[i] = (val_signed + DILITHIUM_Q as i32) as u32 % (DILITHIUM_Q as u32);
    }
    Ok(poly)
}

/// Samples a PolyVecL from CBD_eta, using incrementing nonces for each polynomial.
pub fn sample_polyvecl_cbd_eta<P: DilithiumParams>(
    seed: &[u8; P::SEED_KEY_BYTES],
    initial_nonce: u8,
    eta: u32,
) -> Result<PolyVecL<P>, SignError> {
    let mut pv = PolyVecL::<P>::zero();
    let mut current_nonce = initial_nonce;
    for i in 0..P::L_DIM {
        pv.polys[i] = sample_poly_cbd_eta::<P>(seed, current_nonce, eta)?;
        current_nonce = current_nonce.wrapping_add(1);
    }
    Ok(pv)
}

/// Samples a PolyVecK from CBD_eta, using incrementing nonces for each polynomial.
pub fn sample_polyveck_cbd_eta<P: DilithiumParams>(
    seed: &[u8; P::SEED_KEY_BYTES],
    initial_nonce: u8,
    eta: u32,
) -> Result<PolyVecK<P>, SignError> {
    let mut pv = PolyVecK::<P>::zero();
    let mut current_nonce = initial_nonce;
    for i in 0..P::K_DIM {
        pv.polys[i] = sample_poly_cbd_eta::<P>(seed, current_nonce, eta)?;
        current_nonce = current_nonce.wrapping_add(1);
    }
    Ok(pv)
}

/// Samples a PolyVecL (vector `y`) with coefficients uniformly in `[-gamma1+1, gamma1-1]`.
/// Uses SHAKE256(key_seed_for_y || kappa_nonce) as randomness source.
///
/// # Arguments
/// * `key_seed_for_y`: 32-byte seed (Dilithium's `K`).
/// * `kappa_nonce`: A 16-bit nonce (the `kappa` counter from Fiat-Shamir with Aborts).
/// * `gamma1`: The `gamma1` parameter (e.g., `P::GAMMA1_PARAM`).
///
/// # Returns
/// A `PolyVecL<P>` with coefficients in `[-gamma1+1, gamma1-1]`, represented in `[0, Q-1]`.
///
/// # Implementation Notes (FIPS 203, Algorithm 10, line 4 / Algorithm 23 `ExpandMask`)
/// - For each coefficient, sample bits from SHAKE256 until a value `z` is obtained.
/// - Reduce `z` modulo `2*gamma1 - 1`. Result is `val_in_range`.
/// - The coefficient is `gamma1 - 1 - val_in_range`. This maps to `[-(gamma1-1), gamma1-1]`.
/// - Store as `(coeff + Q) mod Q`.
pub fn sample_polyvecl_uniform_gamma1<P: DilithiumParams>(
    key_seed_for_y: &[u8; P::SEED_KEY_BYTES],
    kappa_nonce: u16,
    gamma1: u32,
) -> Result<PolyVecL<P>, SignError> {
    // TODO: Implement uniform sampling in `[-gamma1+1, gamma1-1]` using SHAKE256.
    // This is FIPS 203 Algorithm 23: ExpandMask.
    // Needs to determine how many bits to sample from SHAKE per coefficient based on gamma1.
    // E.g., if gamma1 = 2^17, range is approx 2^18 wide. Sample 18 bits.
    // For gamma1 = (Q-1)/88, the range is large.
    // The algorithm samples z from {0, ..., 2*gamma1 - 2}, then coeff = gamma1 - 1 - z.
    let mut pv = PolyVecL::<P>::zero();
    let mod_val = 2 * gamma1 -1; // Values will be in [0, 2*gamma1-2]
    let bits_per_z = (mod_val as f64).log2().ceil() as usize; // Number of bits needed for z
    let bytes_per_z_sample = (bits_per_z + 7) / 8;

    for i in 0..P::L_DIM {
        let mut xof = ShakeXof256::new();
        xof.update(key_seed_for_y).map_err(SignError::from_algo)?;
        xof.update(&kappa_nonce.to_le_bytes()).map_err(SignError::from_algo)?; // kappa (nonce for y)
        xof.update(&[i as u8]).map_err(SignError::from_algo)?; // Domain sep for poly in vec

        for j in 0..DILITHIUM_N {
            let mut z_val: u32;
            loop {
                let mut sample_bytes = vec![0u8; bytes_per_z_sample];
                xof.squeeze(&mut sample_bytes).map_err(SignError::from_algo)?;
                
                // Interpret bytes as u32 (little-endian, up to bits_per_z)
                z_val = 0;
                for k in 0..bytes_per_z_sample {
                    z_val |= (sample_bytes[k] as u32) << (8*k);
                }
                z_val &= (1 << bits_per_z) - 1; // Mask to required bits

                if z_val < mod_val { // Rejection sampling
                    break;
                }
            }
            let coeff_signed = (gamma1 - 1) as i32 - (z_val as i32);
            pv.polys[i].coeffs[j] = (coeff_signed + DILITHIUM_Q as i32) as u32 % (DILITHIUM_Q as u32);
        }
    }
    Ok(pv)
}

/// Samples the challenge polynomial `c` from a 32-byte seed `c_tilde_seed`.
/// `c` has `tau` coefficients equal to +1 or -1, others are 0.
/// Uses SHAKE256(c_tilde_seed) to determine positions and signs.
///
/// # Arguments
/// * `c_tilde_seed`: A 32-byte seed.
/// * `tau`: The number of non-zero coefficients in `c` (e.g., `P::TAU_PARAM`).
///
/// # Returns
/// The challenge polynomial `c`.
///
/// # Implementation Notes (FIPS 203, Algorithm 8: SampleInBall)
/// - Sample 8 bits from SHAKE256 for each of the `tau` positions `p_i`.
/// - If a position `p_i` is already taken by a previous `p_j`, try `p_i+1`, `p_i+2`, etc. (modulo N).
/// - Sample `tau` sign bits from SHAKE256. The `i`-th sign bit determines sign of `c_{p_i}`.
pub fn sample_challenge_c<P: DilithiumParams>(
    c_tilde_seed: &[u8; 32], // DILITHIUM_SYMBYTES
    tau: u32,
) -> Result<Polynomial<DilithiumPolyModParams>, SignError> {
    // TODO: Implement Algorithm 8: SampleInBall from FIPS 203.
    let mut c_poly = Polynomial::<DilithiumPolyModParams>::zero();
    let mut xof = ShakeXof256::new();
    xof.update(c_tilde_seed).map_err(SignError::from_algo)?;

    // Buffer for signs (tau bits needed)
    let mut signs_buf = vec![0u8; (tau as usize + 7) / 8];
    xof.squeeze(&mut signs_buf).map_err(SignError::from_algo)?;
    
    let mut positions_taken = [false; DILITHIUM_N];
    let mut count = 0;
    let mut shake_byte_buf = [0u8; 1];

    for k in 0..tau {
        let mut pos: usize;
        loop {
            xof.squeeze(&mut shake_byte_buf).map_err(SignError::from_algo)?;
            pos = shake_byte_buf[0] as usize; // pos in [0, 255]
            if !positions_taken[pos] {
                break;
            }
        }
        positions_taken[pos] = true;

        let sign_bit = (signs_buf[k as usize / 8] >> (k as usize % 8)) & 1;
        if sign_bit == 0 {
            c_poly.coeffs[pos] = 1;
        } else {
            c_poly.coeffs[pos] = DILITHIUM_Q as u32 - 1; // -1 mod Q
        }
        count += 1;
    }
    // All other coefficients remain 0.
    Ok(c_poly)
}