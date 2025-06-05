//! Serialization and deserialization functions for Dilithium per FIPS 203.

use super::polyvec::{PolyVecL, PolyVecK};
use algorithms::poly::serialize::{CoefficientPacker, CoefficientUnpacker, DefaultCoefficientSerde};
use params::pqc::dilithium::{DilithiumParams as DilithiumSignParams, DILITHIUM_N, DILITHIUM_Q};
use crate::error::{Error as SignError};

/// Packs public key (ρ, t1) according to Algorithm 13.
pub fn pack_public_key<P: DilithiumSignParams>(
    rho_seed: &[u8; 32], // SEED_RHO_BYTES is always 32
    t1_vec: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    let mut pk_bytes = Vec::with_capacity(P::PUBLIC_KEY_BYTES);
    
    // Pack ρ
    pk_bytes.extend_from_slice(rho_seed);
    
    // Pack t1 (each coefficient uses 10 bits for all parameter sets)
    for i in 0..P::K_DIM {
        let packed_poly = DefaultCoefficientSerde::pack_coeffs(&t1_vec.polys[i], 10)
            .map_err(SignError::from_algo)?;
        pk_bytes.extend_from_slice(&packed_poly);
    }
    
    if pk_bytes.len() != P::PUBLIC_KEY_BYTES {
        return Err(SignError::Serialization(format!(
            "Public key size mismatch: expected {}, got {}", 
            P::PUBLIC_KEY_BYTES, pk_bytes.len()
        )));
    }
    
    Ok(pk_bytes)
}

/// Unpacks public key from bytes according to Algorithm 14.
pub fn unpack_public_key<P: DilithiumSignParams>(
    pk_bytes: &[u8],
) -> Result<([u8; 32], PolyVecK<P>), SignError> {
    if pk_bytes.len() != P::PUBLIC_KEY_BYTES {
        return Err(SignError::Deserialization(format!(
            "Public key size mismatch: expected {}, got {}", 
            P::PUBLIC_KEY_BYTES, pk_bytes.len()
        )));
    }
    
    // Unpack ρ
    let mut rho_seed = [0u8; 32];
    rho_seed.copy_from_slice(&pk_bytes[0..32]);
    
    // Unpack t1
    let mut t1_vec = PolyVecK::<P>::zero();
    let mut offset = P::SEED_RHO_BYTES;
    let bytes_per_poly = DILITHIUM_N * 10 / 8; // 320 bytes
    
    for i in 0..P::K_DIM {
        let poly_bytes = &pk_bytes[offset..offset + bytes_per_poly];
        t1_vec.polys[i] = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, 10)
            .map_err(SignError::from_algo)?;
        offset += bytes_per_poly;
    }
    
    Ok((rho_seed, t1_vec))
}

/// Packs secret key (ρ, K, tr, s1, s2, t0) according to Algorithm 15.
pub fn pack_secret_key<P: DilithiumSignParams>(
    rho_seed: &[u8; 32],    // SEED_RHO_BYTES is always 32
    k_seed: &[u8; 32],      // SEED_KEY_BYTES is always 32
    tr_hash: &[u8; 32],     // HASH_TR_BYTES is always 32
    s1_vec: &PolyVecL<P>,
    s2_vec: &PolyVecK<P>,
    t0_vec: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    let mut sk_bytes = Vec::with_capacity(P::SECRET_KEY_BYTES);
    
    // Pack ρ, K, tr
    sk_bytes.extend_from_slice(rho_seed);
    sk_bytes.extend_from_slice(k_seed);
    sk_bytes.extend_from_slice(tr_hash);
    
    // Calculate bits needed for s1, s2 encoding
    let eta_bits = if P::ETA_S1S2 == 2 { 3 } else { 4 }; // η=2 needs 3 bits, η=4 needs 4 bits
    
    // Pack s1 (coefficients in [-η, η])
    for i in 0..P::L_DIM {
        let mut temp_poly = s1_vec.polys[i].clone();
        // Map from [-η, η] to [0, 2η]
        for c in temp_poly.coeffs.iter_mut() {
            let centered = (*c as i32).rem_euclid(DILITHIUM_Q as i32);
            let adjusted = if centered > (DILITHIUM_Q / 2) as i32 {
                centered - DILITHIUM_Q as i32
            } else {
                centered
            };
            *c = (adjusted + P::ETA_S1S2 as i32) as u32;
        }
        let packed = DefaultCoefficientSerde::pack_coeffs(&temp_poly, eta_bits)
            .map_err(SignError::from_algo)?;
        sk_bytes.extend_from_slice(&packed);
    }
    
    // Pack s2 (same as s1)
    for i in 0..P::K_DIM {
        let mut temp_poly = s2_vec.polys[i].clone();
        for c in temp_poly.coeffs.iter_mut() {
            let centered = (*c as i32).rem_euclid(DILITHIUM_Q as i32);
            let adjusted = if centered > (DILITHIUM_Q / 2) as i32 {
                centered - DILITHIUM_Q as i32
            } else {
                centered
            };
            *c = (adjusted + P::ETA_S1S2 as i32) as u32;
        }
        let packed = DefaultCoefficientSerde::pack_coeffs(&temp_poly, eta_bits)
            .map_err(SignError::from_algo)?;
        sk_bytes.extend_from_slice(&packed);
    }
    
    // Pack t0 (coefficients in (-2^(d-1), 2^(d-1)])
    let t0_offset = 1 << (P::D_PARAM - 1);
    for i in 0..P::K_DIM {
        let mut temp_poly = t0_vec.polys[i].clone();
        for c in temp_poly.coeffs.iter_mut() {
            let centered = (*c as i32).rem_euclid(DILITHIUM_Q as i32);
            let adjusted = if centered > (DILITHIUM_Q / 2) as i32 {
                centered - DILITHIUM_Q as i32
            } else {
                centered
            };
            *c = (adjusted + t0_offset) as u32;
        }
        let packed = DefaultCoefficientSerde::pack_coeffs(&temp_poly, P::D_PARAM as usize)
            .map_err(SignError::from_algo)?;
        sk_bytes.extend_from_slice(&packed);
    }
    
    if sk_bytes.len() != P::SECRET_KEY_BYTES {
        return Err(SignError::Serialization(format!(
            "Secret key size mismatch: expected {}, got {}", 
            P::SECRET_KEY_BYTES, sk_bytes.len()
        )));
    }
    
    Ok(sk_bytes)
}

/// Unpacks secret key from bytes according to Algorithm 16.
pub fn unpack_secret_key<P: DilithiumSignParams>(
    sk_bytes: &[u8],
) -> Result<(
    [u8; 32], // rho
    [u8; 32], // k
    [u8; 32], // tr
    PolyVecL<P>,
    PolyVecK<P>,
    PolyVecK<P>,
), SignError> {
    if sk_bytes.len() != P::SECRET_KEY_BYTES {
        return Err(SignError::Deserialization(format!(
            "Secret key size mismatch: expected {}, got {}", 
            P::SECRET_KEY_BYTES, sk_bytes.len()
        )));
    }
    
    let mut offset = 0;
    
    // Unpack ρ, K, tr
    let mut rho_seed = [0u8; 32];
    rho_seed.copy_from_slice(&sk_bytes[offset..offset + 32]);
    offset += 32;
    
    let mut k_seed = [0u8; 32];
    k_seed.copy_from_slice(&sk_bytes[offset..offset + 32]);
    offset += 32;
    
    let mut tr_hash = [0u8; 32];
    tr_hash.copy_from_slice(&sk_bytes[offset..offset + 32]);
    offset += 32;
    
    // Calculate sizes
    let eta_bits = if P::ETA_S1S2 == 2 { 3 } else { 4 };
    let bytes_per_s_poly = DILITHIUM_N * eta_bits / 8;
    let bytes_per_t0_poly = DILITHIUM_N * P::D_PARAM as usize / 8;
    
    // Unpack s1
    let mut s1_vec = PolyVecL::<P>::zero();
    for i in 0..P::L_DIM {
        let poly_bytes = &sk_bytes[offset..offset + bytes_per_s_poly];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, eta_bits)
            .map_err(SignError::from_algo)?;
        // Map back from [0, 2η] to [-η, η]
        for c in temp_poly.coeffs.iter_mut() {
            let val = (*c as i32) - P::ETA_S1S2 as i32;
            *c = ((val + DILITHIUM_Q as i32) % DILITHIUM_Q as i32) as u32;
        }
        s1_vec.polys[i] = temp_poly;
        offset += bytes_per_s_poly;
    }
    
    // Unpack s2
    let mut s2_vec = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM {
        let poly_bytes = &sk_bytes[offset..offset + bytes_per_s_poly];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, eta_bits)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() {
            let val = (*c as i32) - P::ETA_S1S2 as i32;
            *c = ((val + DILITHIUM_Q as i32) % DILITHIUM_Q as i32) as u32;
        }
        s2_vec.polys[i] = temp_poly;
        offset += bytes_per_s_poly;
    }
    
    // Unpack t0
    let mut t0_vec = PolyVecK::<P>::zero();
    let t0_offset = 1 << (P::D_PARAM - 1);
    for i in 0..P::K_DIM {
        let poly_bytes = &sk_bytes[offset..offset + bytes_per_t0_poly];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, P::D_PARAM as usize)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() {
            let val = (*c as i32) - t0_offset;
            *c = ((val + DILITHIUM_Q as i32) % DILITHIUM_Q as i32) as u32;
        }
        t0_vec.polys[i] = temp_poly;
        offset += bytes_per_t0_poly;
    }
    
    Ok((rho_seed, k_seed, tr_hash, s1_vec, s2_vec, t0_vec))
}

/// Packs signature (c̃, z, h) according to Algorithm 17.
pub fn pack_signature<P: DilithiumSignParams>(
    c_tilde_seed: &[u8; 32], // SEED_C_TILDE_BYTES is always 32
    z_vec: &PolyVecL<P>,
    h_hint_poly: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    let mut sig_bytes = Vec::with_capacity(P::SIGNATURE_SIZE);
    
    // Pack c̃
    sig_bytes.extend_from_slice(c_tilde_seed);
    
    // Pack z (coefficients in [-γ1+β, γ1-β])
    for i in 0..P::L_DIM {
        let mut temp_poly = z_vec.polys[i].clone();
        for c in temp_poly.coeffs.iter_mut() {
            let centered = (*c as i32).rem_euclid(DILITHIUM_Q as i32);
            let adjusted = if centered > (DILITHIUM_Q / 2) as i32 {
                centered - DILITHIUM_Q as i32
            } else {
                centered
            };
            // Map to [0, 2(γ1-β)]
            *c = (adjusted + (P::GAMMA1_PARAM - P::BETA_PARAM) as i32) as u32;
        }
        let packed = DefaultCoefficientSerde::pack_coeffs(&temp_poly, P::GAMMA1_BITS)
            .map_err(SignError::from_algo)?;
        sig_bytes.extend_from_slice(&packed);
    }
    
    // Pack h as sparse representation
    // Collect indices where h=1
    let mut hint_indices = Vec::new();
    for i in 0..P::K_DIM {
        for j in 0..DILITHIUM_N {
            if h_hint_poly.polys[i].coeffs[j] == 1 {
                hint_indices.push((i, j));
            }
        }
    }
    
    // Encode indices (simplified encoding - in practice uses more efficient packing)
    // For each hint: encode poly index (log2(K) bits) and coeff index (8 bits)
    let poly_bits = (P::K_DIM as f32).log2().ceil() as usize;
    let total_hint_bits = hint_indices.len() * (poly_bits + 8);
    let hint_bytes = (total_hint_bits + 7) / 8;
    
    let mut hint_packed = vec![0u8; hint_bytes];
    let mut bit_pos = 0;
    
    for (poly_idx, coeff_idx) in hint_indices {
        // Pack polynomial index
        for b in 0..poly_bits {
            if (poly_idx >> b) & 1 == 1 {
                hint_packed[bit_pos / 8] |= 1 << (bit_pos % 8);
            }
            bit_pos += 1;
        }
        // Pack coefficient index (8 bits)
        for b in 0..8 {
            if (coeff_idx >> b) & 1 == 1 {
                hint_packed[bit_pos / 8] |= 1 << (bit_pos % 8);
            }
            bit_pos += 1;
        }
    }
    
    // Pad to signature size
    sig_bytes.extend_from_slice(&hint_packed);
    sig_bytes.resize(P::SIGNATURE_SIZE, 0);
    
    Ok(sig_bytes)
}

/// Unpacks signature from bytes according to Algorithm 18.
pub fn unpack_signature<P: DilithiumSignParams>(
    sig_bytes: &[u8],
) -> Result<([u8; 32], PolyVecL<P>, PolyVecK<P>), SignError> {
    if sig_bytes.len() != P::SIGNATURE_SIZE {
        return Err(SignError::Deserialization(format!(
            "Signature size mismatch: expected {}, got {}", 
            P::SIGNATURE_SIZE, sig_bytes.len()
        )));
    }
    
    let mut offset = 0;
    
    // Unpack c̃
    let mut c_tilde_seed = [0u8; 32];
    c_tilde_seed.copy_from_slice(&sig_bytes[offset..offset + 32]);
    offset += 32;
    
    // Unpack z
    let mut z_vec = PolyVecL::<P>::zero();
    let bytes_per_z_poly = DILITHIUM_N * P::GAMMA1_BITS / 8;
    
    for i in 0..P::L_DIM {
        let poly_bytes = &sig_bytes[offset..offset + bytes_per_z_poly];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, P::GAMMA1_BITS)
            .map_err(SignError::from_algo)?;
        // Map back from [0, 2(γ1-β)] to [-γ1+β, γ1-β]
        for c in temp_poly.coeffs.iter_mut() {
            let val = (*c as i32) - (P::GAMMA1_PARAM - P::BETA_PARAM) as i32;
            *c = ((val + DILITHIUM_Q as i32) % DILITHIUM_Q as i32) as u32;
        }
        z_vec.polys[i] = temp_poly;
        offset += bytes_per_z_poly;
    }
    
    // Unpack h (simplified - real implementation needs proper sparse unpacking)
    let mut h_hint_poly = PolyVecK::<P>::zero();
    let hint_bytes = &sig_bytes[offset..];
    
    // Parse hint indices
    let poly_bits = (P::K_DIM as f32).log2().ceil() as usize;
    let mut bit_pos = 0;
    let mut hints_read = 0;
    
    while hints_read < P::OMEGA_PARAM as usize && bit_pos + poly_bits + 8 <= hint_bytes.len() * 8 {
        // Read polynomial index
        let mut poly_idx = 0;
        for b in 0..poly_bits {
            if (hint_bytes[bit_pos / 8] >> (bit_pos % 8)) & 1 == 1 {
                poly_idx |= 1 << b;
            }
            bit_pos += 1;
        }
        
        // Read coefficient index
        let mut coeff_idx = 0;
        for b in 0..8 {
            if (hint_bytes[bit_pos / 8] >> (bit_pos % 8)) & 1 == 1 {
                coeff_idx |= 1 << b;
            }
            bit_pos += 1;
        }
        
        if poly_idx < P::K_DIM && coeff_idx < DILITHIUM_N {
            h_hint_poly.polys[poly_idx].coeffs[coeff_idx] = 1;
            hints_read += 1;
        }
    }
    
    Ok((c_tilde_seed, z_vec, h_hint_poly))
}

/// Packs w1 for computing challenge hash.
pub fn pack_polyveck_w1<P: DilithiumSignParams>(
    w1_vec: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    let mut packed = Vec::new();
    
    for i in 0..P::K_DIM {
        let packed_poly = DefaultCoefficientSerde::pack_coeffs(&w1_vec.polys[i], P::W1_BITS)
            .map_err(SignError::from_algo)?;
        packed.extend_from_slice(&packed_poly);
    }
    
    Ok(packed)
}