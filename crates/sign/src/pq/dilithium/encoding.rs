// File: crates/sign/src/pq/dilithium/encoding.rs
//! Serialization (packing) and deserialization (unpacking) functions for Dilithium
//! public keys, secret keys, and signatures, according to FIPS 203 specifications.

use super::polyvec::{DilithiumPolyModParams, PolyVec, PolyVecL, PolyVecK};
use algorithms::poly::polynomial::Polynomial;
// Assuming DefaultCoefficientSerde is for generic bit packing
use algorithms::poly::serialize::{CoefficientPacker, CoefficientUnpacker, DefaultCoefficientSerde};
use params::pqc::dilithium::{DilithiumParams, DILITHIUM_N, DILITHIUM_Q};
use crate::error::{Error as SignError, Result as SignResult};

// Constants for byte lengths of seeds, etc., matching Dilithium specification.
// These should align with P::SEED_RHO_BYTES, P::SEED_KEY_BYTES etc. from DilithiumParams
const SEED_RHO_BYTES_CONST: usize = 32;
const SEED_K_BYTES_CONST: usize = 32; // Seed K for y and PRF in challenge
const HASH_TR_BYTES_CONST: usize = 32; // Output of H(pk) for tr
const SEED_C_TILDE_BYTES_CONST: usize = 32;


/// Packs the public key `(rho, t1)` into a byte vector.
/// `rho`: `P::SEED_RHO_BYTES` (typically 32 bytes).
/// `t1`: `PolyVecK<P>`, each coefficient packed into `P::D_PARAM` bits.
/// Total size should match `P::PUBLIC_KEY_BYTES`.
pub fn pack_public_key<P: DilithiumParams>(
    rho_seed: &[u8; P::SEED_RHO_BYTES],
    t1_vec: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    // TODO: Implement packing of t1. Each polynomial in t1_vec has its coefficients
    // (which are in [0, 2^(Q_BITS - D_PARAM) - 1]) packed into P::D_PARAM bits.
    // The `algorithms::poly::serialize::DefaultCoefficientSerde::pack_coeffs` can be used.
    // Ensure total output length matches P::PUBLIC_KEY_BYTES.
    let mut pk_bytes = Vec::with_capacity(P::PUBLIC_KEY_BYTES);
    pk_bytes.extend_from_slice(rho_seed);

    for i in 0..P::K_DIM {
        let poly_t1_i = &t1_vec.polys[i];
        // Coefficients of t1 are in [0, 2^(Q_BITS - D_PARAM) - 1], so they inherently fit in D_PARAM bits if D_PARAM is chosen correctly.
        // No further mapping to a smaller range is needed before packing, just ensure they are < 2^D_PARAM.
        let packed_poly = DefaultCoefficientSerde::pack_coeffs(poly_t1_i, P::D_PARAM as usize)
            .map_err(SignError::from_algo)?;
        pk_bytes.extend_from_slice(&packed_poly);
    }

    if pk_bytes.len() != P::PUBLIC_KEY_BYTES {
        return Err(SignError::Serialization(format!("Public key packing length mismatch. Expected {}, got {}", P::PUBLIC_KEY_BYTES, pk_bytes.len())));
    }
    Ok(pk_bytes)
}

/// Unpacks a public key from bytes into `(rho, t1)`.
pub fn unpack_public_key<P: DilithiumParams>(
    pk_bytes: &[u8],
) -> Result<([u8; P::SEED_RHO_BYTES], PolyVecK<P>), SignError> {
    if pk_bytes.len() != P::PUBLIC_KEY_BYTES {
        return Err(SignError::Deserialization(format!("Public key unpacking length mismatch. Expected {}, got {}", P::PUBLIC_KEY_BYTES, pk_bytes.len())));
    }
    let mut rho_seed = [0u8; P::SEED_RHO_BYTES];
    rho_seed.copy_from_slice(&pk_bytes[0..P::SEED_RHO_BYTES]);

    let mut t1_vec = PolyVecK::<P>::zero();
    let mut current_pos = P::SEED_RHO_BYTES;
    let bytes_per_poly_t1 = (DILITHIUM_N * P::D_PARAM as usize + 7) / 8;

    for i in 0..P::K_DIM {
        if current_pos + bytes_per_poly_t1 > pk_bytes.len() {
            return Err(SignError::Deserialization("Insufficient bytes for t1 unpacking".into()));
        }
        let poly_bytes = &pk_bytes[current_pos .. current_pos + bytes_per_poly_t1];
        t1_vec.polys[i] = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, P::D_PARAM as usize)
            .map_err(SignError::from_algo)?;
        current_pos += bytes_per_poly_t1;
    }
    Ok((rho_seed, t1_vec))
}

/// Packs the secret key `(rho, K, tr, s1, s2, t0)` into a byte vector.
/// `rho`, `K`, `tr` are byte strings.
/// `s1`, `s2`: `PolyVecL/K`, coefficients packed to `P::ETA_S1S2` bits (signed, so map to positive first).
/// `t0`: `PolyVecK`, coefficients in `(-2^(D-1), 2^(D-1)]`, packed to `P::D_PARAM` bits.
/// Total size should match `P::SECRET_KEY_BYTES`.
pub fn pack_secret_key<P: DilithiumParams>(
    rho_seed: &[u8; P::SEED_RHO_BYTES],
    k_seed: &[u8; P::SEED_KEY_BYTES], // SEED_K_ZETA_BYTES previously
    tr_hash: &[u8; HASH_TR_BYTES_CONST],
    s1_vec: &PolyVecL<P>,
    s2_vec: &PolyVecK<P>,
    t0_vec: &PolyVecK<P>, // t0 contains signed coefficients
) -> Result<Vec<u8>, SignError> {
    // TODO: Implement packing for s1, s2, t0 based on their specific bit-widths and signedness.
    // - s1, s2 coefficients are in [-eta, eta]. Map to [0, 2*eta] then pack ETA_S1S2 bits.
    // - t0 coefficients are in (-2^(D-1), 2^(D-1)]. Map to [0, 2^D-1] then pack D_PARAM bits.
    // Ensure total output length matches P::SECRET_KEY_BYTES.
    let mut sk_bytes = Vec::with_capacity(P::SECRET_KEY_BYTES);
    sk_bytes.extend_from_slice(rho_seed);
    sk_bytes.extend_from_slice(k_seed);
    sk_bytes.extend_from_slice(tr_hash);

    // Packing s1 (coeffs in [-ETA_S1S2, ETA_S1S2])
    let eta_s1s2 = P::ETA_S1S2 as i32;
    let bits_s1s2 = (2 * eta_s1s2 + 1).next_power_of_two().trailing_zeros() as usize; // smallest #bits to hold 2*eta+1 values
    for poly_s1_i in s1_vec.polys.iter() {
        let mut temp_poly = poly_s1_i.clone();
        for c in temp_poly.coeffs.iter_mut() {
            let mut centered_c = *c as i32;
            if centered_c > DILITHIUM_Q as i32 / 2 { centered_c -= DILITHIUM_Q as i32; } // to [-Q/2, Q/2]
            *c = (centered_c + eta_s1s2) as u32; // map to [0, 2*eta]
        }
        let packed_poly = DefaultCoefficientSerde::pack_coeffs(&temp_poly, bits_s1s2)
            .map_err(SignError::from_algo)?;
        sk_bytes.extend_from_slice(&packed_poly);
    }
    // Packing s2 (coeffs in [-ETA_S1S2, ETA_S1S2])
    for poly_s2_i in s2_vec.polys.iter() {
        let mut temp_poly = poly_s2_i.clone();
        for c in temp_poly.coeffs.iter_mut() {
            let mut centered_c = *c as i32;
            if centered_c > DILITHIUM_Q as i32 / 2 { centered_c -= DILITHIUM_Q as i32; }
            *c = (centered_c + eta_s1s2) as u32;
        }
        let packed_poly = DefaultCoefficientSerde::pack_coeffs(&temp_poly, bits_s1s2)
            .map_err(SignError::from_algo)?;
        sk_bytes.extend_from_slice(&packed_poly);
    }
    
    // Packing t0 (coeffs in (-2^(D-1), 2^(D-1)])
    let d_val = P::D_PARAM as i32;
    let t0_offset = 1 << (d_val - 1); // 2^(D-1)
    for poly_t0_i in t0_vec.polys.iter() {
        let mut temp_poly = poly_t0_i.clone();
        for c in temp_poly.coeffs.iter_mut() {
            let mut centered_c = *c as i32;
            if centered_c > DILITHIUM_Q as i32 / 2 { centered_c -= DILITHIUM_Q as i32; }
            // Map coeff from (-2^(D-1), 2^(D-1)] to [0, 2^D-1] approximately for packing
            // Exact packing scheme for t0 needs to be precise. This is a placeholder.
            *c = (centered_c + t0_offset) as u32; // Example: map to roughly positive range
        }
        // Pack into D_PARAM bits
        let packed_poly = DefaultCoefficientSerde::pack_coeffs(&temp_poly, P::D_PARAM as usize)
            .map_err(SignError::from_algo)?;
        sk_bytes.extend_from_slice(&packed_poly);
    }

    if sk_bytes.len() != P::SECRET_KEY_BYTES {
         return Err(SignError::Serialization(format!("Secret key packing length mismatch. Expected {}, got {}", P::SECRET_KEY_BYTES, sk_bytes.len())));
    }
    Ok(sk_bytes)
}

/// Unpacks a secret key from bytes into its components.
pub fn unpack_secret_key<P: DilithiumParams>(
    sk_bytes: &[u8],
) -> Result<(
    [u8; P::SEED_RHO_BYTES],
    [u8; P::SEED_KEY_BYTES],
    [u8; HASH_TR_BYTES_CONST],
    PolyVecL<P>,
    PolyVecK<P>,
    PolyVecK<P>, // t0_vec
), SignError> {
    // TODO: Implement unpacking. Inverse of pack_secret_key.
    // Ensure lengths and offsets are precise based on P's parameters for ETA_S1S2 and D_PARAM packing.
    if sk_bytes.len() != P::SECRET_KEY_BYTES {
        return Err(SignError::Deserialization(format!("Secret key unpacking length mismatch. Expected {}, got {}", P::SECRET_KEY_BYTES, sk_bytes.len())));
    }
    let mut rho_seed = [0u8; P::SEED_RHO_BYTES];
    let mut k_seed = [0u8; P::SEED_KEY_BYTES];
    let mut tr_hash = [0u8; HASH_TR_BYTES_CONST];
    
    let mut current_pos = 0;
    rho_seed.copy_from_slice(&sk_bytes[current_pos .. current_pos + P::SEED_RHO_BYTES]);
    current_pos += P::SEED_RHO_BYTES;
    k_seed.copy_from_slice(&sk_bytes[current_pos .. current_pos + P::SEED_KEY_BYTES]);
    current_pos += P::SEED_KEY_BYTES;
    tr_hash.copy_from_slice(&sk_bytes[current_pos .. current_pos + HASH_TR_BYTES_CONST]);
    current_pos += HASH_TR_BYTES_CONST;

    let eta_s1s2 = P::ETA_S1S2 as i32;
    let bits_s1s2 = (2 * eta_s1s2 + 1).next_power_of_two().trailing_zeros() as usize;
    let bytes_per_poly_s1s2 = (DILITHIUM_N * bits_s1s2 + 7) / 8;
    
    let mut s1_vec = PolyVecL::<P>::zero();
    for i in 0..P::L_DIM {
        let poly_bytes = &sk_bytes[current_pos .. current_pos + bytes_per_poly_s1s2];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, bits_s1s2)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() { *c = (*c as i32 - eta_s1s2) as u32 % (DILITHIUM_Q as u32); } // Map back
        s1_vec.polys[i] = temp_poly;
        current_pos += bytes_per_poly_s1s2;
    }

    let mut s2_vec = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM {
        let poly_bytes = &sk_bytes[current_pos .. current_pos + bytes_per_poly_s1s2];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, bits_s1s2)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() { *c = (*c as i32 - eta_s1s2) as u32 % (DILITHIUM_Q as u32); } // Map back
        s2_vec.polys[i] = temp_poly;
        current_pos += bytes_per_poly_s1s2;
    }
    
    let mut t0_vec = PolyVecK::<P>::zero();
    let d_val = P::D_PARAM as i32;
    let t0_offset = 1 << (d_val - 1);
    let bytes_per_poly_t0 = (DILITHIUM_N * P::D_PARAM as usize + 7) / 8;
    for i in 0..P::K_DIM {
        let poly_bytes = &sk_bytes[current_pos .. current_pos + bytes_per_poly_t0];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, P::D_PARAM as usize)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() { *c = (*c as i32 - t0_offset) as u32 % (DILITHIUM_Q as u32); } // Map back
        t0_vec.polys[i] = temp_poly;
        current_pos += bytes_per_poly_t0;
    }

    Ok((rho_seed, k_seed, tr_hash, s1_vec, s2_vec, t0_vec))
}


/// Packs the signature `(c_tilde_seed, z_vec, h_packed_indices)` into a byte vector.
/// `c_tilde_seed`: `SEED_C_TILDE_BYTES_CONST` (32 bytes).
/// `z_vec`: `PolyVecL<P>`, coefficients packed to `bits_for_z`.
/// `h_packed_indices`: `PolyVecK<P>` representing hints, packed efficiently.
/// Total size should match `P::SIGNATURE_SIZE`.
pub fn pack_signature<P: DilithiumParams>(
    c_tilde_seed: &[u8; SEED_C_TILDE_BYTES_CONST],
    z_vec: &PolyVecL<P>,
    h_hint_poly: &PolyVecK<P>, // PolyVecK where each coeff is 0 or 1 (hint bit)
) -> Result<Vec<u8>, SignError> {
    // TODO: Implement signature packing per FIPS 203 Appendix A.3.
    // - c_tilde_seed is copied directly.
    // - z_vec: coefficients are in [-gamma1+beta, gamma1-beta]. Map to [0, 2*(gamma1-beta)] then pack.
    //   The number of bits `bits_for_z = ceil(log2(2*(gamma1-beta)+1))`.
    // - h_hint_poly: This needs to be packed as a list of OMEGA indices where hint is 1.
    //   This is complex. For the skeleton, we'll just pack it as if it's dense for placeholder.
    let mut sig_bytes = Vec::with_capacity(P::SIGNATURE_SIZE);
    sig_bytes.extend_from_slice(c_tilde_seed);

    let bits_for_z = P::GAMMA1_BITS; // From DilithiumParams: ceil(log2(2*gamma1 - 2*beta + 1))
    for poly_z_i in z_vec.polys.iter() {
        let mut temp_poly_z = poly_z_i.clone();
        for c in temp_poly_z.coeffs.iter_mut() {
            let mut centered_c = *c as i32;
            if centered_c > DILITHIUM_Q as i32 / 2 { centered_c -= DILITHIUM_Q as i32; }
            // Map from [-gamma1+beta, gamma1-beta] to [0, 2*(gamma1-beta)]
            *c = (centered_c + (P::GAMMA1_PARAM - P::BETA_PARAM) as i32) as u32;
        }
        let packed_poly = DefaultCoefficientSerde::pack_coeffs(&temp_poly_z, bits_for_z as usize)
            .map_err(SignError::from_algo)?;
        sig_bytes.extend_from_slice(&packed_poly);
    }

    // Packing h (Placeholder: pack as dense 1-bit coefficients)
    // Actual Dilithium packs Omega indices.
    let packed_h_len = P::SIGNATURE_SIZE - sig_bytes.len();
    let mut temp_h_packed_bits = Vec::new();
    for poly_h_i in h_hint_poly.polys.iter() {
        for &coeff_h in poly_h_i.coeffs.iter() {
            temp_h_packed_bits.push(coeff_h == 1); // Store as bools
        }
    }
    // Now pack these booleans into bytes
    let mut packed_h_bytes = vec![0u8; (temp_h_packed_bits.len() + 7) / 8];
    for (i, &bit) in temp_h_packed_bits.iter().enumerate() {
        if bit {
            packed_h_bytes[i/8] |= 1 << (i%8);
        }
    }
    // Ensure packed_h_bytes is exactly packed_h_len, pad or truncate if necessary
    // This placeholder is not correct for Dilithium's sparse hint packing.
    if packed_h_bytes.len() >= packed_h_len {
        sig_bytes.extend_from_slice(&packed_h_bytes[..packed_h_len]);
    } else {
        sig_bytes.extend_from_slice(&packed_h_bytes);
        sig_bytes.resize(P::SIGNATURE_SIZE, 0u8); // Pad if too short
    }


    if sig_bytes.len() != P::SIGNATURE_SIZE {
        return Err(SignError::Serialization(format!("Signature packing length mismatch. Expected {}, got {}", P::SIGNATURE_SIZE, sig_bytes.len())));
    }
    Ok(sig_bytes)
}

/// Unpacks a signature from bytes into `(c_tilde_seed, z_vec, h_hint_poly)`.
pub fn unpack_signature<P: DilithiumParams>(
    sig_bytes: &[u8],
) -> Result<([u8; SEED_C_TILDE_BYTES_CONST], PolyVecL<P>, PolyVecK<P>), SignError> {
    // TODO: Implement signature unpacking per FIPS 203 Appendix A.3.
    // Inverse of pack_signature. Unpack c_tilde_seed, z_vec, and the OMEGA hint indices.
    if sig_bytes.len() != P::SIGNATURE_SIZE {
        return Err(SignError::Deserialization(format!("Signature unpacking length mismatch. Expected {}, got {}", P::SIGNATURE_SIZE, sig_bytes.len())));
    }
    let mut c_tilde_seed = [0u8; SEED_C_TILDE_BYTES_CONST];
    c_tilde_seed.copy_from_slice(&sig_bytes[0..SEED_C_TILDE_BYTES_CONST]);
    let mut current_pos = SEED_C_TILDE_BYTES_CONST;

    let mut z_vec = PolyVecL::<P>::zero();
    let bits_for_z = P::GAMMA1_BITS;
    let bytes_per_poly_z = (DILITHIUM_N * bits_for_z as usize + 7) / 8;
    for i in 0..P::L_DIM {
        let poly_bytes = &sig_bytes[current_pos .. current_pos + bytes_per_poly_z];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, bits_for_z as usize)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() {
            // Map from [0, 2*(gamma1-beta)] back to [-gamma1+beta, gamma1-beta]
            // Then map to [0, Q-1]
            let mapped_val = *c as i32 - (P::GAMMA1_PARAM - P::BETA_PARAM) as i32;
            *c = (mapped_val + DILITHIUM_Q as i32) as u32 % (DILITHIUM_Q as u32);
        }
        z_vec.polys[i] = temp_poly;
        current_pos += bytes_per_poly_z;
    }

    // Unpacking h_hint_poly (Placeholder: unpack as dense 1-bit coefficients)
    // Actual Dilithium unpacks OMEGA indices and reconstructs h.
    let mut h_hint_poly = PolyVecK::<P>::zero();
    let packed_h_bytes = &sig_bytes[current_pos..];
    let mut bit_idx = 0;
    'outer: for i in 0..P::K_DIM {
        for j in 0..DILITHIUM_N {
            if bit_idx / 8 >= packed_h_bytes.len() { break 'outer; }
            if (packed_h_bytes[bit_idx / 8] >> (bit_idx % 8)) & 1 == 1 {
                h_hint_poly.polys[i].coeffs[j] = 1;
            }
            bit_idx += 1;
        }
    }
    
    Ok((c_tilde_seed, z_vec, h_hint_poly))
}

/// Packs PolyVecK `w1` into bytes. Coefficients are in `[0, 2*gamma2-1]`.
/// Each coefficient is packed into `ceil(log2(2*gamma2))` bits.
pub fn pack_polyveck_w1<P: DilithiumParams>(w1_vec: &PolyVecK<P>) -> Result<Vec<u8>, SignError> {
    // TODO: Implement packing for w1 for H_chal(mu || pack(w1)).
    // The size of w1_packed is (k * POLYW1_PACKED_BYTES)
    // POLYW1_PACKED_BYTES = N * bits_for_w1_coeff / 8
    // bits_for_w1_coeff = ceil(log2(2*gamma2))
    // For Dilithium2, gamma2 = (Q-1)/88. 2*gamma2 approx Q/44. log2(Q/44) approx 23-5.4 = 17.6. So 18 bits.
    // This implies P must define a specific bitwidth for w1 elements.
    // Let's assume P::W1_BITS.
    let mut w1_packed_bytes = Vec::new();
    for poly_w1_i in w1_vec.polys.iter() {
        let packed_poly = DefaultCoefficientSerde::pack_coeffs(poly_w1_i, P::W1_BITS as usize)
            .map_err(SignError::from_algo)?;
        w1_packed_bytes.extend_from_slice(&packed_poly);
    }
    Ok(w1_packed_bytes)
}