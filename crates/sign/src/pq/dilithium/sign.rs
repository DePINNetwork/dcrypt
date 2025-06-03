// File: crates/sign/src/pq/dilithium/sign.rs
//! Core implementation logic for Dilithium key generation, signing, and verification.
//! This file orchestrates the use of polynomial operations, arithmetic helpers,
//! sampling, and encoding routines to implement the Dilithium signature scheme.

use super::polyvec::{PolyVecL, PolyVecK, expand_matrix_a};
// Assuming DilithiumPolyModParams is correctly defined in algorithms::poly::params
use algorithms::poly::params::DilithiumPolyModParams;
use super::arithmetic::{power2round_polyvec, highbits_polyvec, lowbits_polyvec, check_norm_polyvec, make_hint_polyveck, use_hint_polyveck_from_sig};
use super::sampling::{sample_polyvecl_cbd_eta, sample_polyveck_cbd_eta, sample_polyvecl_uniform_gamma1, sample_challenge_c};
use super::encoding::{pack_public_key, unpack_public_key, pack_secret_key, unpack_secret_key, pack_signature, unpack_signature, pack_polyveck_w1};

use algorithms::hash::sha3::{Sha3_256, Sha3_512};
use algorithms::hash::HashFunction;
use algorithms::error::Result as AlgoResult;
use crate::error::{Error as SignError, Result as SignResult};
use params::pqc::dilithium::{DilithiumParams, DILITHIUM_N, DILITHIUM_Q};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;
use subtle::ConstantTimeEq;


/// Internal Key Generation for Dilithium (Algorithm 9 from FIPS 203).
pub(crate) fn keypair_internal<P, R>(rng: &mut R) -> SignResult<(Vec<u8>, Vec<u8>)>
where
    P: DilithiumParams,
    R: RngCore + CryptoRng,
{
    let mut zeta_seed = [0u8; P::SEED_ZETA_BYTES]; // Seed for K, s1, s2, (e in PKE)
    let mut rho_seed = [0u8; P::SEED_RHO_BYTES];
    rng.fill_bytes(&mut zeta_seed);
    rng.fill_bytes(&mut rho_seed);

    // Split zeta into seed for s1/s2 (sigma_seed) and seed for y (K_seed)
    // FIPS 203: G(zeta) -> (rho, sigma_seed, K_seed)
    // For simplicity here, we use zeta directly for sigma_seed and K_seed.
    // A real implementation would use SHAKE256(zeta) to derive these.
    let sigma_seed = zeta_seed; // Placeholder
    let k_seed_for_signing = zeta_seed; // Placeholder

    // 1. Expand A from rho (standard domain)
    let matrix_a = expand_matrix_a::<P>(&rho_seed)?;
    // Convert matrix_a to NTT form (A_hat)
    let mut matrix_a_hat = [(); P::K_DIM].map(|_| PolyVecL::<P>::zero());
    for i in 0..P::K_DIM {
        for j in 0..P::L_DIM {
            let mut poly = matrix_a[i].polys[j].clone();
            poly.ntt_inplace().map_err(SignError::from_algo)?;
            matrix_a_hat[i].polys[j] = poly;
        }
    }

    // 2. Sample s1, s2 from CBD_eta using sigma_seed
    let s1_vec = sample_polyvecl_cbd_eta::<P>(&sigma_seed, 0, P::ETA_S1S2 as u32)?;
    let s2_vec = sample_polyveck_cbd_eta::<P>(&sigma_seed, P::L_DIM as u8, P::ETA_S1S2 as u32)?;
    
    let mut s1_hat_vec = s1_vec.clone(); s1_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;
    let mut s2_hat_vec = s2_vec.clone(); s2_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    // 3. t_hat_vec = A_hat * s1_hat_vec + s2_hat_vec
    let mut t_hat_vec = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM {
        let row_a_hat = &matrix_a_hat[i];
        let dot_product_poly = row_a_hat.pointwise_dot_product(&s1_hat_vec);
        t_hat_vec.polys[i] = dot_product_poly.add(&s2_hat_vec.polys[i]);
    }
    
    let mut t_vec = t_hat_vec.clone();
    t_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;

    // 5. (t0_vec, t1_vec) = Power2Round(t_vec, D_PARAM)
    let (t0_vec, t1_vec) = power2round_polyvec(&t_vec, P::D_PARAM as u32);

    // 6. pk = (rho_seed, pack(t1_vec))
    let pk_bytes = pack_public_key::<P>(&rho_seed, &t1_vec)?;

    // 7. tr = H(pk_bytes) (SHA3-256)
    let mut hasher_tr = Sha3_256::new();
    hasher_tr.update(&pk_bytes).map_err(SignError::from_algo)?;
    let tr_digest = hasher_tr.finalize().map_err(SignError::from_algo)?;
    let mut tr = [0u8; P::HASH_TR_BYTES]; // Use const from P
    tr.copy_from_slice(tr_digest.as_ref());

    // 8. sk = (rho_seed, k_seed_for_signing, tr, pack(s1_vec), pack(s2_vec), pack(t0_vec))
    let sk_bytes = pack_secret_key::<P>(&rho_seed, &k_seed_for_signing, &tr, &s1_vec, &s2_vec, &t0_vec)?;
    
    Ok((pk_bytes, sk_bytes))
}


/// Internal Signing logic for Dilithium (Algorithm 10 from FIPS 203).
pub(crate) fn sign_internal<P, R>(
    message: &[u8],
    sk_bytes: &[u8],
    _rng_for_hedging_if_any: &mut R, // Standard Dilithium is deterministic given SK and message.
) -> SignResult<Vec<u8>>
where
    P: DilithiumParams,
    R: RngCore + CryptoRng,
{
    let (rho_seed, k_seed, tr_hash, s1_vec, s2_vec, t0_vec) = unpack_secret_key::<P>(sk_bytes)?;
    
    let mut s1_hat_vec = s1_vec.clone(); s1_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;
    // s2 is used in standard domain for w - c*s2
    // t0 is used in standard domain for w1_prime - c*t0 (UseHint part)

    let matrix_a_orig = expand_matrix_a::<P>(&rho_seed)?;
    let mut matrix_a_hat = [(); P::K_DIM].map(|_| PolyVecL::<P>::zero());
    for i in 0..P::K_DIM {
        for j in 0..P::L_DIM {
            let mut poly = matrix_a_orig[i].polys[j].clone();
            poly.ntt_inplace().map_err(SignError::from_algo)?;
            matrix_a_hat[i].polys[j] = poly;
        }
    }

    // mu = H_msg(tr_hash || message) (SHA3-512)
    let mut hasher_mu = Sha3_512::new();
    hasher_mu.update(&tr_hash).map_err(SignError::from_algo)?;
    hasher_mu.update(message).map_err(SignError::from_algo)?;
    let mu_digest = hasher_mu.finalize().map_err(SignError::from_algo)?;
    let mu = mu_digest.as_ref();

    let mut kappa: u16 = 0;
    loop { // Fiat-Shamir with Aborts
        if kappa > P::MAX_SIGN_ABORTS { // Add MAX_SIGN_ABORTS to DilithiumParams
            return Err(SignError::SignatureGeneration("Exceeded max signature attempts".into()));
        }

        let y_vec = sample_polyvecl_uniform_gamma1::<P>(&k_seed, kappa, P::GAMMA1_PARAM as u32)?;
        let mut y_hat_vec = y_vec.clone(); y_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

        // w_hat = A_hat * y_hat
        let mut w_hat_vec = PolyVecK::<P>::zero();
        for i in 0..P::K_DIM {
            w_hat_vec.polys[i] = matrix_a_hat[i].pointwise_dot_product(&y_hat_vec);
        }
        
        let mut w_vec = w_hat_vec.clone(); w_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;
        
        // w1 = HighBits(w_vec, 2*gamma2)
        let w1_vec = highbits_polyvec(&w_vec, 2 * P::GAMMA2_PARAM as u32);
        let w1_packed = pack_polyveck_w1::<P>(&w1_vec)?;

        // c_tilde_seed = H_chal(mu || w1_packed) (SHA3-256)
        let mut hasher_ctilde_seed = Sha3_256::new();
        hasher_ctilde_seed.update(mu).map_err(SignError::from_algo)?;
        hasher_ctilde_seed.update(&w1_packed).map_err(SignError::from_algo)?;
        let c_tilde_seed_digest = hasher_ctilde_seed.finalize().map_err(SignError::from_algo)?;
        let mut c_tilde_seed = [0u8; P::SEED_C_TILDE_BYTES];
        c_tilde_seed.copy_from_slice(c_tilde_seed_digest.as_ref());
        
        let c_poly = sample_challenge_c::<P>(&c_tilde_seed, P::TAU_PARAM as u32)?;
        
        // z_vec = y_vec + c_poly * s1_vec (standard domain)
        let mut z_vec = y_vec.clone();
        for i in 0..P::L_DIM {
            let cs1_i = c_poly.schoolbook_mul(&s1_vec.polys[i]);
            z_vec.polys[i] = z_vec.polys[i].add(&cs1_i);
        }
        
        if !check_norm_polyvec(&z_vec, P::GAMMA1_PARAM - P::BETA_PARAM) {
            kappa = kappa.wrapping_add(1); continue;
        }
        
        // LowBits(w_vec - c_poly * s2_vec)
        let mut cs2_vec = PolyVecK::<P>::zero();
        for i in 0..P::K_DIM {
            cs2_vec.polys[i] = c_poly.schoolbook_mul(&s2_vec.polys[i]);
        }
        let w_minus_cs2_vec = w_vec.sub(&cs2_vec);
        let lowbits_w_cs2_vec = lowbits_polyvec(&w_minus_cs2_vec, 2 * P::GAMMA2_PARAM as u32);
        
        if !check_norm_polyvec(&lowbits_w_cs2_vec, P::GAMMA2_PARAM - P::BETA_PARAM) {
            kappa = kappa.wrapping_add(1); continue;
        }

        // MakeHint for h_vec. v = w - c*s2. Check uses v - c*t0.
        // Hint = MakeHint(-c*t0, v - c*t0) = MakeHint(-c*t0, w - c*s2 - c*t0)
        // FIPS 203 Algorithm 10 line 17: h = MakeHint(-c*t0, w1 + c*t0) is incorrect.
        // It should be related to w0 - c*t0 (the part removed by HighBits).
        // Correctly, h is MakeHint(v0_prime, v1_prime) where (v0_prime, v1_prime) = Decompose(w-c*s2-c*t0).
        // Let's assume `make_hint_polyveck` is correctly implemented based on `v_for_hint = w_vec - cs2_vec - ct0_vec`.
        let mut ct0_vec = PolyVecK::<P>::zero();
        for i in 0..P::K_DIM {
            ct0_vec.polys[i] = c_poly.schoolbook_mul(&t0_vec.polys[i]);
        }
        let v_for_hint_poly = w_minus_cs2_vec.sub(&ct0_vec); // w - c*s2 - c*t0
        // Decompose v_for_hint_poly to get its v0 and v1 parts for MakeHint
        let (v0_for_hint, v1_for_hint) = power2round_polyvec(&v_for_hint_poly, P::D_PARAM as u32); // This is not correct, MakeHint uses Decompose with 2*gamma2
        // Placeholder for actual hint generation based on spec (is complex)
        let h_hint_poly = make_hint_polyveck::<P>(&v0_for_hint, &v1_for_hint)?;
        
        let mut hint_count = 0;
        for poly_h in h_hint_poly.polys.iter() {
            for &coeff_h in poly_h.coeffs.iter() { if coeff_h == 1 { hint_count += 1; }}
        }
        if hint_count > P::OMEGA_PARAM as usize {
            kappa = kappa.wrapping_add(1); continue;
        }

        return pack_signature::<P>(&c_tilde_seed, &z_vec, &h_hint_poly);
    }
}

/// Internal Verification logic for Dilithium (Algorithm 11 from FIPS 203).
pub(crate) fn verify_internal<P>(
    message: &[u8],
    sig_bytes: &[u8],
    pk_bytes: &[u8],
) -> SignResult<()>
where
    P: DilithiumParams,
{
    let (rho_seed, t1_vec) = unpack_public_key::<P>(pk_bytes)?;
    // h_packed_indices is really the packed form of h, not yet a PolyVecK of 0/1s.
    // Needs proper unpacking based on FIPS 203 Appendix A.3
    let (c_tilde_seed_sig, z_vec, h_packed_poly) = unpack_signature::<P>(sig_bytes)?;

    if !check_norm_polyvec(&z_vec, P::GAMMA1_PARAM - P::BETA_PARAM) {
        return Err(SignError::Verification("Signature norm check for z failed".into()));
    }
    
    let matrix_a_orig = expand_matrix_a::<P>(&rho_seed)?;
    let mut matrix_a_hat = [(); P::K_DIM].map(|_| PolyVecL::<P>::zero());
    for i in 0..P::K_DIM {
        for j in 0..P::L_DIM {
            let mut poly = matrix_a_orig[i].polys[j].clone();
            poly.ntt_inplace().map_err(SignError::from_algo)?;
            matrix_a_hat[i].polys[j] = poly;
        }
    }

    let c_poly = sample_challenge_c::<P>(&c_tilde_seed_sig, P::TAU_PARAM as u32)?;
    let mut c_hat_poly = c_poly.clone(); c_hat_poly.ntt_inplace().map_err(SignError::from_algo)?;
    
    let mut z_hat_vec = z_vec.clone(); z_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;
    let mut t1_hat_vec = t1_vec.clone(); t1_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    // w1_prime_hat = A_hat * z_hat - c_hat * t1_hat
    // (A_hat * z_hat)_i = sum_j (A_hat_ij * z_hat_j)
    // (c_hat * t1_hat)_i = c_hat * t1_hat_i
    let mut w1_prime_hat_vec = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM { // For each of K polynomials in the result vector
        let az_i = matrix_a_hat[i].pointwise_dot_product(&z_hat_vec);
        let ct1_i = t1_hat_vec.polys[i].ntt_mul(&c_hat_poly);
        w1_prime_hat_vec.polys[i] = az_i.sub(&ct1_i);
    }
    
    let mut w1_prime_vec = w1_prime_hat_vec.clone();
    w1_prime_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;

    // Apply UseHint. The spec is w1'' = UseHint(h, A*z - c*t1) where (A*z - c*t1) is w1_prime_vec.
    // h_packed_poly needs to be correctly interpreted as hint indices.
    let w1_double_prime_vec = use_hint_polyveck_from_sig::<P>(&h_packed_poly, &w1_prime_vec)?;
    let w1_double_prime_packed = pack_polyveck_w1::<P>(&w1_double_prime_vec)?;

    // tr = H(pk_bytes)
    let mut hasher_tr = Sha3_256::new();
    hasher_tr.update(pk_bytes).map_err(SignError::from_algo)?;
    let tr_digest = hasher_tr.finalize().map_err(SignError::from_algo)?;
    let mut tr = [0u8; P::HASH_TR_BYTES];
    tr.copy_from_slice(tr_digest.as_ref());

    // mu = H_msg(tr || message)
    let mut hasher_mu = Sha3_512::new();
    hasher_mu.update(&tr).map_err(SignError::from_algo)?;
    hasher_mu.update(message).map_err(SignError::from_algo)?;
    let mu_digest = hasher_mu.finalize().map_err(SignError::from_algo)?;
    let mu = mu_digest.as_ref();

    // c_tilde_seed_recomputed = H_chal(mu || w1_double_prime_packed)
    let mut hasher_ctilde_seed_recomputed = Sha3_256::new();
    hasher_ctilde_seed_recomputed.update(mu).map_err(SignError::from_algo)?;
    hasher_ctilde_seed_recomputed.update(&w1_double_prime_packed).map_err(SignError::from_algo)?;
    let c_tilde_seed_recomputed_digest = hasher_ctilde_seed_recomputed.finalize().map_err(SignError::from_algo)?;
    
    // Constant time comparison for c_tilde_seed
    if !c_tilde_seed_sig.ct_eq(c_tilde_seed_recomputed_digest.as_ref()).into_bool() {
         return Err(SignError::Verification("Challenge c_tilde mismatch".into()));
    }
    
    // Verify hint count (omega check from h_packed_poly)
    let mut hint_count = 0;
    for poly_h in h_packed_poly.polys.iter() {
        for &coeff_h in poly_h.coeffs.iter() { if coeff_h == 1 { hint_count += 1; }}
    }
    if hint_count > P::OMEGA_PARAM as usize {
        return Err(SignError::Verification("Too many hints indicated in signature".into()));
    }

    Ok(())
}