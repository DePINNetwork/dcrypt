//! Serialization functions for Dilithium per FIPS 204
//! 
//! Key aspects: 
//! - FIPS-204 compliant HintBitPack/HintBitUnpack encoding that matches final spec.
//! - Challenge hash size varies by security level (32/48/64 bytes).
//! - 32-byte padding added to secret keys to match NIST Round 3 specification.
//! - Uses Z_BITS instead of GAMMA1_BITS for packing z coefficients.

use super::polyvec::{PolyVecL, PolyVecK};
use super::arithmetic::{w1_bits_needed};
use algorithms::poly::serialize::{CoefficientPacker, CoefficientUnpacker, DefaultCoefficientSerde};
use params::pqc::dilithium::{DilithiumSchemeParams, DILITHIUM_N, DILITHIUM_Q};
use crate::error::{Error as SignError};

// ---------------------------------------------------------------------------
// Helper algorithms 24 / 25 – HintBitPack / HintBitUnpack (FIPS‑204 final)
// 
// FIPS 204 §4.2 requires the hint section to be EXACTLY ω + K bytes:
// - First ω bytes: hint indices, ALWAYS ω bytes (padded with 0 if needed)
// - Next K bytes: per-polynomial counters
// ---------------------------------------------------------------------------

/// Packs the hint vector *h* using the final FIPS‑204 "HintBitPack" layout:
///   * first ω bytes  — coefficient indices (0‑255), padded with zeros to exactly ω bytes
///   * then   K bytes — per‑polynomial counters (number of indices that belong
///                      to each row).  The total number of 1‑bits MUST equal
///                      the sum of the counters and be ≤ ω.
/// 
/// FIPS 204 §4.2 requires the output to be EXACTLY ω + K bytes, hence the padding.
/// 
/// Note: The same coefficient index may appear in multiple polynomials. This is valid
/// per FIPS-204 as the counters disambiguate which indices belong to which polynomial.
fn pack_hints_bitpacked<P: DilithiumSchemeParams>(
    h_hint_poly: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    let mut idx_bytes = Vec::with_capacity(P::OMEGA_PARAM as usize);
    let mut counters = vec![0u8; P::K_DIM];

    // Step 1: Collect all hint indices (maintaining polynomial grouping)
    for (row, poly) in h_hint_poly.polys.iter().enumerate() {
        for (col, &bit) in poly.coeffs.iter().enumerate() {
            if bit == 1 {
                if idx_bytes.len() >= P::OMEGA_PARAM as usize {
                    return Err(SignError::Serialization(
                        "Too many hints for signature".into(),
                    ));
                }
                idx_bytes.push(col as u8);
                counters[row] = counters[row].saturating_add(1);
            }
        }
    }

    // Step 2: Pad to exactly ω bytes as required by FIPS 204
    idx_bytes.resize(P::OMEGA_PARAM as usize, 0);

    // Step 3: Concatenate indices and counters
    let mut packed = idx_bytes;  // Always exactly ω bytes
    packed.extend_from_slice(&counters);  // Plus K bytes
    Ok(packed)  // Total = ω + K bytes
}

/// Inverse of `pack_hints_bitpacked` (Algorithm 25).
/// Expects exactly ω + K bytes: ω bytes of indices (possibly padded with zeros)
/// followed by K bytes of counters.
fn unpack_hints_bitpacked<P: DilithiumSchemeParams>(
    bytes: &[u8],
) -> Result<(PolyVecK<P>, usize), SignError> {
    if bytes.len() < P::OMEGA_PARAM as usize + P::K_DIM {
        return Err(SignError::Deserialization("Truncated hint section".into()));
    }

    // Split at exactly ω bytes (not based on content)
    let (idx_bytes, counters_bytes) = bytes.split_at(P::OMEGA_PARAM as usize);

    let mut h_poly = PolyVecK::<P>::zero();
    let mut total = 0usize;

    let mut offset = 0usize;
    for (row, &cnt) in counters_bytes.iter().enumerate() {
        let cnt_usize = cnt as usize;
        if offset + cnt_usize > P::OMEGA_PARAM as usize {
            return Err(SignError::Deserialization("Counter overflow in hint section".into()));
        }
        
        // Only read cnt_usize indices, ignoring any padding
        for &idx in &idx_bytes[offset .. offset + cnt_usize] {
            if idx as usize >= DILITHIUM_N {
                return Err(SignError::Deserialization("Hint index out of range".into()));
            }
            h_poly.polys[row].coeffs[idx as usize] = 1;
        }
        offset += cnt_usize;
        total += cnt_usize;
    }

    // Total 1-bits must not exceed ω (but can be less due to padding)
    if total > P::OMEGA_PARAM as usize {
        return Err(SignError::Deserialization("Too many hint bits".into()));
    }

    Ok((h_poly, total))
}

/// Packs public key (ρ, t1) according to Algorithm 13.
pub fn pack_public_key<P: DilithiumSchemeParams>(
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
pub fn unpack_public_key<P: DilithiumSchemeParams>(
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
/// NIST Round 3 adds 32 bytes of padding at the end.
pub fn pack_secret_key<P: DilithiumSchemeParams>(
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
            let centered = (*c as i64).rem_euclid(DILITHIUM_Q as i64) as i32;
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
            let centered = (*c as i64).rem_euclid(DILITHIUM_Q as i64) as i32;
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
            let centered = (*c as i64).rem_euclid(DILITHIUM_Q as i64) as i32;
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
    
    // NIST Round 3: Add 32 bytes of padding at the end of the secret key
    let content_size = sk_bytes.len();
    let expected_size = P::SECRET_KEY_BYTES;
    
    if content_size < expected_size {
        // Add padding to match PQClean/NIST format
        let padding_size = expected_size - content_size;
        if padding_size == 32 {
            sk_bytes.resize(expected_size, 0);
        } else {
            return Err(SignError::Serialization(format!(
                "Unexpected padding size needed: {} bytes (expected 0 or 32)", 
                padding_size
            )));
        }
    }
    
    if sk_bytes.len() != P::SECRET_KEY_BYTES {
        return Err(SignError::Serialization(format!(
            "Secret key size mismatch after padding: expected {}, got {}", 
            P::SECRET_KEY_BYTES, sk_bytes.len()
        )));
    }
    
    Ok(sk_bytes)
}

/// Unpacks secret key from bytes according to Algorithm 16.
/// NIST Round 3 includes 32 bytes of padding at the end.
pub fn unpack_secret_key<P: DilithiumSchemeParams>(
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
        // Map from [0..2η] → signed (-η..+η), then repackage into [0..Q)
        for c in temp_poly.coeffs.iter_mut() {
            let signed = (*c as i32) - (P::ETA_S1S2 as i32);
            if signed < 0 {
                *c = (signed + DILITHIUM_Q as i32) as u32;
            } else {
                *c = signed as u32;
            }
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
            let signed = (*c as i32) - (P::ETA_S1S2 as i32);
            if signed < 0 {
                *c = (signed + DILITHIUM_Q as i32) as u32;
            } else {
                *c = signed as u32;
            }
        }
        s2_vec.polys[i] = temp_poly;
        offset += bytes_per_s_poly;
    }
    
    // Unpack t0 - Keep t₀ centered instead of converting negatives to large positives
    let mut t0_vec = PolyVecK::<P>::zero();
    let t0_offset = 1 << (P::D_PARAM - 1);
    for i in 0..P::K_DIM {
        let poly_bytes = &sk_bytes[offset..offset + bytes_per_t0_poly];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, P::D_PARAM as usize)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() {
            let signed = (*c as i32) - (t0_offset as i32);
            // Keep t₀ centered using proper modular arithmetic
            *c = ((signed + DILITHIUM_Q as i32) % DILITHIUM_Q as i32) as u32;
        }
        t0_vec.polys[i] = temp_poly;
        offset += bytes_per_t0_poly;
    }
    
    // NIST Round 3: Handle 32-byte padding at the end
    let remaining = sk_bytes.len() - offset;
    if remaining == 32 {
        // Skip 32 bytes of padding - optionally verify it's all zeros
        if sk_bytes[offset..].iter().any(|&b| b != 0) {
            return Err(SignError::Deserialization(
                "Non-zero padding found in secret key".into()
            ));
        }
    } else if remaining != 0 {
        return Err(SignError::Deserialization(format!(
            "Unexpected {} bytes remaining after unpacking secret key", 
            remaining
        )));
    }
    
    Ok((rho_seed, k_seed, tr_hash, s1_vec, s2_vec, t0_vec))
}

/// Packs signature (c̃, z, h) according to FIPS 204 Algorithm 17 with variable challenge size
/// Uses Z_BITS instead of GAMMA1_BITS for packing z coefficients
pub fn pack_signature<P: DilithiumSchemeParams>(
    c_tilde_seed: &[u8], // Now variable size: 32/48/64 bytes
    z_vec: &PolyVecL<P>,
    h_hint_poly: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    // Verify challenge seed is the correct size
    if c_tilde_seed.len() != P::CHALLENGE_BYTES {
        return Err(SignError::Serialization(format!(
            "Challenge seed size mismatch: expected {}, got {}", 
            P::CHALLENGE_BYTES, c_tilde_seed.len()
        )));
    }
    
    let mut sig_bytes = Vec::with_capacity(P::SIGNATURE_SIZE);
    
    // Pack c̃ (variable size: 32/48/64 bytes)
    sig_bytes.extend_from_slice(c_tilde_seed);
    
    // Pack z (coefficients in [-γ1+β, γ1-β])
    for i in 0..P::L_DIM {
        let mut temp_poly = z_vec.polys[i].clone();
        for c in temp_poly.coeffs.iter_mut() {
            let centered = (*c as i64).rem_euclid(DILITHIUM_Q as i64) as i32;
            let adjusted = if centered > (DILITHIUM_Q / 2) as i32 {
                centered - DILITHIUM_Q as i32
            } else {
                centered
            };
            // Map to [0, 2(γ1-β)]
            *c = (adjusted + (P::GAMMA1_PARAM - P::BETA_PARAM) as i32) as u32;
        }
        // Use Z_BITS instead of GAMMA1_BITS
        let packed = DefaultCoefficientSerde::pack_coeffs(&temp_poly, P::Z_BITS)
            .map_err(SignError::from_algo)?;
        sig_bytes.extend_from_slice(&packed);
    }
    
    // Pack h using HintBitPack encoding (FIPS 204 Algorithm 24)
    let hint_bytes = pack_hints_bitpacked::<P>(h_hint_poly)?;
    sig_bytes.extend_from_slice(&hint_bytes);

    // Final length check (no manual padding)
    if sig_bytes.len() != P::SIGNATURE_SIZE {
        return Err(SignError::Serialization(format!(
            "Signature size mismatch: expected {}, got {}",
            P::SIGNATURE_SIZE,
            sig_bytes.len(),
        )));
    }

    Ok(sig_bytes)
}

/// Packs w1 for computing challenge hash using FIPS 204 final w1Encode.
/// Packs full gamma-bucket indices: 6 bits for Dilithium2, 5 bits for Dilithium3/5.
pub fn pack_polyveck_w1<P: DilithiumSchemeParams>(
    w1_vec: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    // FIPS 204 final: use full bucket indices
    // - Dilithium2: 6 bits for r1 ∈ [0,44]
    // - Dilithium3/5: 5 bits for r1 ∈ [0,16]
    let bits_per_coeff = w1_bits_needed::<P>();
    let total_bits = P::K_DIM as usize * DILITHIUM_N * bits_per_coeff as usize;
    let total_bytes = (total_bits + 7) / 8;  // Round up to nearest byte
    let mut packed = vec![0u8; total_bytes];
    
    // Pack coefficients MSB-first as per FIPS 204 Algorithm 28
    let mut bit_offset = 0;
    for poly in &w1_vec.polys {
        for &coeff in &poly.coeffs {
            // Pack bits_per_coeff bits of the coefficient (full r1 value)
            for b in (0..bits_per_coeff).rev() {
                let bit_val = ((coeff >> b) & 1) as u8;
                let byte_idx = bit_offset / 8;
                let bit_in_byte = 7 - (bit_offset % 8);
                packed[byte_idx] |= bit_val << bit_in_byte;
                bit_offset += 1;
            }
        }
    }
    
    Ok(packed)
}

/// Unpacks signature from bytes according to FIPS 204 Algorithm 18 with variable challenge size
/// Uses Z_BITS instead of GAMMA1_BITS for unpacking z coefficients
pub fn unpack_signature<P: DilithiumSchemeParams>(
    sig_bytes: &[u8],
) -> Result<(Vec<u8>, PolyVecL<P>, PolyVecK<P>), SignError> {
    if sig_bytes.len() != P::SIGNATURE_SIZE {
        return Err(SignError::Deserialization(format!(
            "Signature size mismatch: expected {}, got {}", 
            P::SIGNATURE_SIZE, sig_bytes.len()
        )));
    }
    
    let mut offset = 0;
    
    // Unpack c̃ (variable size: 32/48/64 bytes)
    let mut c_tilde_seed = vec![0u8; P::CHALLENGE_BYTES];
    c_tilde_seed.copy_from_slice(&sig_bytes[offset..offset + P::CHALLENGE_BYTES]);
    offset += P::CHALLENGE_BYTES;
    
    // Unpack z
    let mut z_vec = PolyVecL::<P>::zero();
    // Use Z_BITS instead of GAMMA1_BITS
    let bytes_per_z_poly = DILITHIUM_N * P::Z_BITS / 8;
    
    for i in 0..P::L_DIM {
        let poly_bytes = &sig_bytes[offset..offset + bytes_per_z_poly];
        // Use Z_BITS instead of GAMMA1_BITS
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, P::Z_BITS)
            .map_err(SignError::from_algo)?;
        // Map back from [0, 2(γ1-β)] to [-γ1+β, γ1-β]
        for c in temp_poly.coeffs.iter_mut() {
            let val = (*c as i32) - (P::GAMMA1_PARAM - P::BETA_PARAM) as i32;
            *c = (val as i64).rem_euclid(DILITHIUM_Q as i64) as u32;
        }
        z_vec.polys[i] = temp_poly;
        offset += bytes_per_z_poly;
    }
    
    // Unpack h using HintBitUnpack decoding (FIPS 204 Algorithm 25)
    let hint_bytes = &sig_bytes[offset..];
    let (h_hint_poly, _hint_cnt) = unpack_hints_bitpacked::<P>(hint_bytes)?;

    Ok((c_tilde_seed, z_vec, h_hint_poly))
}


#[cfg(test)]
mod tests {
    use super::*;
    use params::pqc::dilithium::{Dilithium2Params, Dilithium3Params, Dilithium5Params};
    
    #[test]
    fn test_roundtrip_hints_basic() {
        // Test basic roundtrip with hints in different polynomials
        let mut h = PolyVecK::<Dilithium2Params>::zero();
        h.polys[1].coeffs[5] = 1;
        h.polys[2].coeffs[20] = 1;
        
        let packed = pack_hints_bitpacked::<Dilithium2Params>(&h).unwrap();
        let (unpacked, cnt) = unpack_hints_bitpacked::<Dilithium2Params>(&packed).unwrap();
        
        assert_eq!(cnt, 2, "Hint count mismatch");
        assert_eq!(unpacked.polys[1].coeffs[5], 1, "Lost hint at poly[1].coeff[5]");
        assert_eq!(unpacked.polys[2].coeffs[20], 1, "Lost hint at poly[2].coeff[20]");
        
        // Verify no spurious hints
        for i in 0..Dilithium2Params::K_DIM {
            for j in 0..256 {
                if !((i == 1 && j == 5) || (i == 2 && j == 20)) {
                    assert_eq!(unpacked.polys[i].coeffs[j], 0, 
                        "Spurious hint at poly[{}].coeff[{}]", i, j);
                }
            }
        }
    }
    
    #[test]
    fn test_roundtrip_hints_edge_cases() {
        // Test edge case: hints at coefficient 0 and 255
        let mut h = PolyVecK::<Dilithium2Params>::zero();
        h.polys[0].coeffs[0] = 1;    // First coefficient
        h.polys[3].coeffs[255] = 1;  // Last coefficient
        
        let packed = pack_hints_bitpacked::<Dilithium2Params>(&h).unwrap();
        let (unpacked, cnt) = unpack_hints_bitpacked::<Dilithium2Params>(&packed).unwrap();
        
        assert_eq!(cnt, 2);
        assert_eq!(unpacked.polys[0].coeffs[0], 1, "Lost hint at first position");
        assert_eq!(unpacked.polys[3].coeffs[255], 1, "Lost hint at last position");
    }
    
    #[test]
    fn test_hint_order_preservation() {
        // Test that the order of hints is preserved correctly
        // This is critical for signature verification
        let positions = vec![(0, 10), (0, 50), (1, 30), (2, 5), (3, 100)];
        
        let mut h = PolyVecK::<Dilithium2Params>::zero();
        for &(poly_idx, coeff_idx) in &positions {
            h.polys[poly_idx].coeffs[coeff_idx] = 1;
        }
        
        let packed = pack_hints_bitpacked::<Dilithium2Params>(&h).unwrap();
        let (unpacked, cnt) = unpack_hints_bitpacked::<Dilithium2Params>(&packed).unwrap();
        
        assert_eq!(cnt, positions.len());
        
        // Verify each position
        for &(poly_idx, coeff_idx) in &positions {
            assert_eq!(unpacked.polys[poly_idx].coeffs[coeff_idx], 1,
                "Hint at poly[{}].coeff[{}] was not preserved", poly_idx, coeff_idx);
        }
        
        // Count total hints to ensure no extras
        let mut total_hints = 0;
        for i in 0..Dilithium2Params::K_DIM {
            for j in 0..256 {
                if unpacked.polys[i].coeffs[j] == 1 {
                    total_hints += 1;
                }
            }
        }
        assert_eq!(total_hints, positions.len(), "Extra hints appeared after unpacking");
    }
    
    #[test]
    fn test_packed_hint_size() {
        // Verify packed size is always ω + K bytes
        let mut h = PolyVecK::<Dilithium2Params>::zero();
        h.polys[0].coeffs[0] = 1;
        
        let packed = pack_hints_bitpacked::<Dilithium2Params>(&h).unwrap();
        assert_eq!(packed.len(), 
            Dilithium2Params::OMEGA_PARAM as usize + Dilithium2Params::K_DIM,
            "Packed hint size should be ω + K bytes");
    }
    
    #[test]
    fn test_hints_maximum_allowed() {
        // Test with maximum allowed hints (ω)
        let mut h = PolyVecK::<Dilithium2Params>::zero();
        let mut hint_count = 0;
        
        // Fill hints up to ω
        'outer: for i in 0..Dilithium2Params::K_DIM {
            for j in 0..256 {
                if hint_count < Dilithium2Params::OMEGA_PARAM as usize {
                    h.polys[i].coeffs[j] = 1;
                    hint_count += 1;
                } else {
                    break 'outer;
                }
            }
        }
        
        let packed = pack_hints_bitpacked::<Dilithium2Params>(&h).unwrap();
        let (unpacked, cnt) = unpack_hints_bitpacked::<Dilithium2Params>(&packed).unwrap();
        
        assert_eq!(cnt, Dilithium2Params::OMEGA_PARAM as usize);
        
        // Verify all hints preserved
        let mut verified_count = 0;
        for i in 0..Dilithium2Params::K_DIM {
            for j in 0..256 {
                if h.polys[i].coeffs[j] == 1 {
                    assert_eq!(unpacked.polys[i].coeffs[j], 1,
                        "Lost hint at poly[{}].coeff[{}]", i, j);
                    verified_count += 1;
                }
            }
        }
        assert_eq!(verified_count, Dilithium2Params::OMEGA_PARAM as usize);
    }
    
    #[test]
    fn test_hint_packing_deterministic() {
        // Verify packing is deterministic
        let mut h = PolyVecK::<Dilithium2Params>::zero();
        h.polys[0].coeffs[42] = 1;
        h.polys[1].coeffs[100] = 1;
        h.polys[2].coeffs[200] = 1;
        
        let packed1 = pack_hints_bitpacked::<Dilithium2Params>(&h).unwrap();
        let packed2 = pack_hints_bitpacked::<Dilithium2Params>(&h).unwrap();
        
        assert_eq!(packed1, packed2, "Hint packing should be deterministic");
    }
    
    #[test]
    fn test_hint_layout_fips204() {
        // Test that the packed format follows FIPS 204 layout:
        // First ω bytes: indices
        // Next K bytes: counters
        let mut h = PolyVecK::<Dilithium2Params>::zero();
        h.polys[0].coeffs[10] = 1;  // Hint in poly 0
        h.polys[1].coeffs[20] = 1;  // Hint in poly 1
        h.polys[1].coeffs[30] = 1;  // Another hint in poly 1
        
        let packed = pack_hints_bitpacked::<Dilithium2Params>(&h).unwrap();
        
        // Check size
        assert_eq!(packed.len(), 
            Dilithium2Params::OMEGA_PARAM as usize + Dilithium2Params::K_DIM);
        
        // Check counters section
        let counters_start = Dilithium2Params::OMEGA_PARAM as usize;
        assert_eq!(packed[counters_start], 1);     // poly 0 has 1 hint
        assert_eq!(packed[counters_start + 1], 2); // poly 1 has 2 hints
        assert_eq!(packed[counters_start + 2], 0); // poly 2 has 0 hints
        assert_eq!(packed[counters_start + 3], 0); // poly 3 has 0 hints
        
        // Check indices section has expected values
        assert_eq!(packed[0], 10);  // First hint index
        assert_eq!(packed[1], 20);  // Second hint index
        assert_eq!(packed[2], 30);  // Third hint index
    }
}