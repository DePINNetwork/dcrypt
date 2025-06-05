//! Core implementation of Dilithium key generation, signing, and verification per FIPS 203.
//!
//! Implements lattice-based signatures using Fiat-Shamir with Aborts.
//! Security based on Module-LWE and Module-SIS problems.
//!
//! Critical invariants (DO NOT MODIFY):
//! - `||z||∞ ≤ γ1 - β` (prevents key recovery)
//! - `||LowBits(w - cs2)||∞ ≤ γ2 - β` (ensures uniformity)
//! - Rejection sampling protects against side-channel leakage
//!
//! Implementation notes:
//! - Signing is deterministic (randomness from key + counter)
//! - Track polynomial domains carefully (standard vs NTT)
//! - Expected signing iterations: 4-7 (varies by parameter set)
//!
//! Internal module - use public `Dilithium2/3/5` types instead.

use super::polyvec::{PolyVecK, expand_matrix_a, matrix_polyvecl_mul};
use algorithms::poly::params::NttModulus;  // FIXED: Import NttModulus from params
use super::arithmetic::{
    power2round_polyvec, highbits_polyvec, lowbits_polyvec, 
    check_norm_polyvec_l, check_norm_polyvec_k,
    make_hint_polyveck, use_hint_polyveck
};
use super::sampling::{
    sample_polyvecl_cbd_eta, sample_polyveck_cbd_eta, 
    sample_polyvecl_uniform_gamma1, sample_challenge_c
};
use super::encoding::{
    pack_public_key, unpack_public_key, pack_secret_key, 
    unpack_secret_key, pack_signature, unpack_signature, pack_polyveck_w1
};

use algorithms::hash::sha3::Sha3_256;
use algorithms::xof::shake::ShakeXof256;
use algorithms::hash::HashFunction;
use algorithms::xof::ExtendableOutputFunction;
use crate::error::{Error as SignError};
use params::pqc::dilithium::{DilithiumParams as DilithiumSignParams, DILITHIUM_N};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

/// Key Generation (Algorithm 9 from FIPS 203)
/// 
/// Generates (pk, sk) where pk = (ρ, t1) and sk = (ρ, K, tr, s1, s2, t0).
/// Matrix A expanded from ρ, secrets s1,s2 from CBD(η).
pub(crate) fn keypair_internal<P, R>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>), SignError>
where
    P: DilithiumSignParams,
    R: RngCore + CryptoRng,
{
    // Step 1: Sample ζ
    let mut zeta_seed = vec![0u8; P::SEED_ZETA_BYTES];
    rng.fill_bytes(&mut zeta_seed);
    
    // Step 2: Expand seeds using G = SHAKE256
    let mut xof = ShakeXof256::new();
    xof.update(&zeta_seed).map_err(SignError::from_algo)?;
    
    let mut seeds = vec![0u8; P::SEED_RHO_BYTES + P::SEED_KEY_BYTES + P::SEED_KEY_BYTES];
    xof.squeeze(&mut seeds).map_err(SignError::from_algo)?;
    
    let mut rho_seed = [0u8; 32];
    let mut sigma_seed = [0u8; 32];
    let mut k_seed = [0u8; 32];
    
    rho_seed.copy_from_slice(&seeds[0..P::SEED_RHO_BYTES]);
    sigma_seed.copy_from_slice(&seeds[P::SEED_RHO_BYTES..P::SEED_RHO_BYTES + P::SEED_KEY_BYTES]);
    k_seed.copy_from_slice(&seeds[P::SEED_RHO_BYTES + P::SEED_KEY_BYTES..]);
    
    // Step 3: Expand A from ρ
    let matrix_a = expand_matrix_a::<P>(&rho_seed)?;
    
    // Convert A to NTT domain (Â)
    let mut matrix_a_hat = Vec::with_capacity(P::K_DIM);
    for i in 0..P::K_DIM {
        let mut row = matrix_a[i].clone();
        row.ntt_inplace().map_err(SignError::from_algo)?; // Keep A in NTT for efficiency
        matrix_a_hat.push(row);
    }
    
    // Step 4: Sample s1, s2
    let s1_vec = sample_polyvecl_cbd_eta::<P>(&sigma_seed, 0, P::ETA_S1S2)?;
    let s2_vec = sample_polyveck_cbd_eta::<P>(&sigma_seed, P::L_DIM as u8, P::ETA_S1S2)?;
    
    // Convert to NTT domain
    let mut s1_hat_vec = s1_vec.clone();
    s1_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;
    
    let mut s2_hat_vec = s2_vec.clone();
    s2_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;
    
    // Step 5: t̂ = Â·ŝ1 + ŝ2
    let mut t_hat_vec = matrix_polyvecl_mul(&matrix_a_hat, &s1_hat_vec);
    t_hat_vec = t_hat_vec.add(&s2_hat_vec);
    
    // Convert back to standard domain
    let mut t_vec = t_hat_vec.clone();
    t_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;
    
    // Step 6: (t0, t1) = Power2Round(t)
    let (t0_vec, t1_vec) = power2round_polyvec(&t_vec, P::D_PARAM);
    
    // Step 7: Pack public key
    let pk_bytes = pack_public_key::<P>(&rho_seed, &t1_vec)?;
    
    // Step 8: tr = H(pk)
    let mut hasher = Sha3_256::new();
    hasher.update(&pk_bytes).map_err(SignError::from_algo)?;
    let tr_digest = hasher.finalize().map_err(SignError::from_algo)?;
    let mut tr = [0u8; 32];
    tr.copy_from_slice(&tr_digest);
    
    // Step 9: Pack secret key
    let sk_bytes = pack_secret_key::<P>(&rho_seed, &k_seed, &tr, &s1_vec, &s2_vec, &t0_vec)?;
    
    Ok((pk_bytes, sk_bytes))
}

/// Signing (Algorithm 10 from FIPS 203)
/// 
/// Produces signature (c̃, z, h) using rejection sampling.
/// Aborts and retries if z or w-cs2 exceed bounds (side-channel protection).
/// Deterministic: y derived from K and counter κ.
pub(crate) fn sign_internal<P, R>(
    message: &[u8],
    sk_bytes: &[u8],
    _rng: &mut R, // Dilithium is deterministic
) -> Result<Vec<u8>, SignError>
where
    P: DilithiumSignParams,
    R: RngCore + CryptoRng,
{
    // Step 1: Unpack secret key
    let (rho_seed, k_seed, tr_hash, s1_vec, s2_vec, t0_vec) = unpack_secret_key::<P>(sk_bytes)?;
    
    // Convert s1 to NTT domain
    let mut s1_hat_vec = s1_vec.clone();
    s1_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;
    
    // Step 2: Expand A
    let matrix_a = expand_matrix_a::<P>(&rho_seed)?;
    let mut matrix_a_hat = Vec::with_capacity(P::K_DIM);
    for i in 0..P::K_DIM {
        let mut row = matrix_a[i].clone();
        row.ntt_inplace().map_err(SignError::from_algo)?;
        matrix_a_hat.push(row);
    }
    
    // Step 3: μ = H(tr || M)
    let mut xof_mu = ShakeXof256::new();
    xof_mu.update(&tr_hash).map_err(SignError::from_algo)?;
    xof_mu.update(message).map_err(SignError::from_algo)?;
    let mut mu = vec![0u8; 64];
    xof_mu.squeeze(&mut mu).map_err(SignError::from_algo)?;
    
    // Step 4: κ = 0
    let mut kappa: u16 = 0;
    
    loop {
        // Check abort condition
        if kappa >= P::MAX_SIGN_ABORTS {
            return Err(SignError::SignatureGeneration {
                algorithm: P::NAME,
                details: "Exceeded max attempts".into(),
            });
        }
        
        // Step 5: y = ExpandMask(K, κ)
        let y_vec = sample_polyvecl_uniform_gamma1::<P>(&k_seed, kappa, P::GAMMA1_PARAM)?;
        
        // Convert to NTT domain
        let mut y_hat_vec = y_vec.clone();
        y_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;
        
        // Step 6: ŵ = Â·ŷ
        let w_hat_vec = matrix_polyvecl_mul(&matrix_a_hat, &y_hat_vec);
        
        // Convert to standard domain
        let mut w_vec = w_hat_vec.clone();
        w_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;
        
        // Step 7: w1 = HighBits(w)
        let w1_vec = highbits_polyvec(&w_vec, 2 * P::GAMMA2_PARAM);
        
        // Step 8: c̃ = H(μ || w1)
        let w1_packed = pack_polyveck_w1::<P>(&w1_vec)?;
        let mut xof_c = ShakeXof256::new();
        xof_c.update(&mu).map_err(SignError::from_algo)?;
        xof_c.update(&w1_packed).map_err(SignError::from_algo)?;
        let mut c_tilde_seed = [0u8; 32];
        xof_c.squeeze(&mut c_tilde_seed).map_err(SignError::from_algo)?;
        
        // Step 9: c = SampleInBall(c̃)
        let c_poly = sample_challenge_c::<P>(&c_tilde_seed, P::TAU_PARAM as u32)?;
        
        // Step 10: z = y + c·s1
        let mut z_vec = y_vec.clone();
        for i in 0..P::L_DIM {
            let cs1_i = c_poly.schoolbook_mul(&s1_vec.polys[i]);
            z_vec.polys[i] = z_vec.polys[i].add(&cs1_i);
        }
        
        // Step 11: Check ||z||∞
        if !check_norm_polyvec_l::<P>(&z_vec, P::GAMMA1_PARAM - P::BETA_PARAM) {
            kappa = kappa.wrapping_add(1);
            continue; // Rejection sampling - critical for security
        }
        
        // Step 12-13: Check low bits of w - c·s2
        let mut cs2_vec = PolyVecK::<P>::zero();
        for i in 0..P::K_DIM {
            cs2_vec.polys[i] = c_poly.schoolbook_mul(&s2_vec.polys[i]);
        }
        let w_minus_cs2 = w_vec.sub(&cs2_vec);
        let r0_vec = lowbits_polyvec(&w_minus_cs2, 2 * P::GAMMA2_PARAM);
        
        if !check_norm_polyvec_k::<P>(&r0_vec, P::GAMMA2_PARAM - P::BETA_PARAM) {
            kappa = kappa.wrapping_add(1);
            continue;
        }
        
        // Step 14-15: Make hint
        let mut ct0_vec = PolyVecK::<P>::zero();
        for i in 0..P::K_DIM {
            ct0_vec.polys[i] = c_poly.schoolbook_mul(&t0_vec.polys[i]);
        }
        let v_for_hint = w_minus_cs2.sub(&ct0_vec);
        let (h_hint_poly, hint_count) = make_hint_polyveck::<P>(&v_for_hint)?;
        
        // Step 16: Check hint count
        if hint_count > P::OMEGA_PARAM as usize {
            kappa = kappa.wrapping_add(1);
            continue; // Too many hints would allow forgeries
        }
        
        // Step 17: Return signature
        return pack_signature::<P>(&c_tilde_seed, &z_vec, &h_hint_poly);
    }
}

/// Verification (Algorithm 11 from FIPS 203)
/// 
/// Accepts if: c̃ = H(μ || UseHint(h, Az - ct1·2^d)) and ||z||∞ ≤ γ1 - β.
/// Strong unforgeability: signatures cannot be forged even with oracle access.
pub(crate) fn verify_internal<P>(
    message: &[u8],
    sig_bytes: &[u8],
    pk_bytes: &[u8],
) -> Result<(), SignError>
where
    P: DilithiumSignParams,
{
    // Step 1: Unpack public key
    let (rho_seed, t1_vec) = unpack_public_key::<P>(pk_bytes)?;
    
    // Step 2: Unpack signature
    let (c_tilde_seed_sig, z_vec, h_hint_poly) = unpack_signature::<P>(sig_bytes)?;
    
    // Step 3: Check ||z||∞
    if !check_norm_polyvec_l::<P>(&z_vec, P::GAMMA1_PARAM - P::BETA_PARAM) {
        return Err(SignError::Verification {
            algorithm: P::NAME,
            details: "z norm check failed".into(),
        });
    }
    
    // Step 4: Expand A
    let matrix_a = expand_matrix_a::<P>(&rho_seed)?;
    let mut matrix_a_hat = Vec::with_capacity(P::K_DIM);
    for i in 0..P::K_DIM {
        let mut row = matrix_a[i].clone();
        row.ntt_inplace().map_err(SignError::from_algo)?;
        matrix_a_hat.push(row);
    }
    
    // Step 5: tr = H(pk)
    let mut hasher = Sha3_256::new();
    hasher.update(pk_bytes).map_err(SignError::from_algo)?;
    let tr_digest = hasher.finalize().map_err(SignError::from_algo)?;
    let mut tr = [0u8; 32];
    tr.copy_from_slice(&tr_digest);
    
    // Step 6: μ = H(tr || M)
    let mut xof_mu = ShakeXof256::new();
    xof_mu.update(&tr).map_err(SignError::from_algo)?;
    xof_mu.update(message).map_err(SignError::from_algo)?;
    let mut mu = vec![0u8; 64];
    xof_mu.squeeze(&mut mu).map_err(SignError::from_algo)?;
    
    // Step 7: c = SampleInBall(c̃)
    let c_poly = sample_challenge_c::<P>(&c_tilde_seed_sig, P::TAU_PARAM as u32)?;
    
    // Convert to NTT domain
    let mut c_hat_poly = c_poly.clone();
    c_hat_poly.ntt_inplace().map_err(SignError::from_algo)?;
    
    let mut z_hat_vec = z_vec.clone();
    z_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;
    
    let mut t1_hat_vec = t1_vec.clone();
    t1_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;
    
    // Step 8: ŵ' = Â·ẑ - ĉ·t̂₁·2^d
    let az_hat = matrix_polyvecl_mul(&matrix_a_hat, &z_hat_vec);
    
    // Scale t1 by 2^d and multiply by c
    let two_d = 1 << P::D_PARAM;
    let mut ct1_scaled_hat = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM {
        let t1_scaled = t1_hat_vec.polys[i].scalar_mul(two_d);
        ct1_scaled_hat.polys[i] = c_hat_poly.ntt_mul(&t1_scaled);
    }
    
    let w_prime_hat_vec = az_hat.sub(&ct1_scaled_hat);
    
    // Convert to standard domain
    let mut w_prime_vec = w_prime_hat_vec.clone();
    w_prime_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;
    
    // Step 9: w₁'' = UseHint(h, w')
    let w1_double_prime_vec = use_hint_polyveck::<P>(&h_hint_poly, &w_prime_vec)?;
    
    // Step 10: c̃' = H(μ || w₁'')
    let w1_double_prime_packed = pack_polyveck_w1::<P>(&w1_double_prime_vec)?;
    let mut xof_c_recompute = ShakeXof256::new();
    xof_c_recompute.update(&mu).map_err(SignError::from_algo)?;
    xof_c_recompute.update(&w1_double_prime_packed).map_err(SignError::from_algo)?;
    let mut c_tilde_seed_recomputed = [0u8; 32];
    xof_c_recompute.squeeze(&mut c_tilde_seed_recomputed).map_err(SignError::from_algo)?;
    
    // Step 11: Verify c̃ = c̃'
    if !bool::from(c_tilde_seed_sig.ct_eq(&c_tilde_seed_recomputed)) {
        return Err(SignError::Verification {
            algorithm: P::NAME,
            details: "Challenge mismatch".into(),
        });
    }
    
    // Step 12: Verify hint count
    let mut hint_count = 0;
    for i in 0..P::K_DIM {
        for j in 0..DILITHIUM_N {
            if h_hint_poly.polys[i].coeffs[j] == 1 {
                hint_count += 1;
            }
        }
    }
    
    if hint_count > P::OMEGA_PARAM as usize {
        return Err(SignError::Verification {
            algorithm: P::NAME,
            details: "Too many hints".into(),
        });
    }
    
    Ok(())
}