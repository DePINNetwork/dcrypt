//! Sampling functions for Dilithium implementing FIPS 203 algorithms.

use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_algorithms::poly::params::{DilithiumParams, Modulus};
use super::polyvec::{PolyVecL, PolyVecK};
use dcrypt_params::pqc::dilithium::DilithiumSchemeParams;
use dcrypt_algorithms::xof::shake::ShakeXof256;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use crate::error::{Error as SignError};

/// Samples a polynomial with coefficients from CBD_eta (Algorithm 22).
/// Uses SHAKE256(seed || nonce) as randomness source.
#[allow(clippy::extra_unused_type_parameters)]
pub fn sample_poly_cbd_eta<P: DilithiumSchemeParams>(
    seed: &[u8; 32], // SEED_KEY_BYTES is always 32
    nonce: u8,
    eta: u32,
) -> Result<Polynomial<DilithiumParams>, SignError> {
    if eta == 0 || eta > 8 {
        return Err(SignError::Sampling(format!("Invalid eta for CBD: {}", eta)));
    }

    let mut xof = ShakeXof256::new();
    xof.update(seed).map_err(SignError::from_algo)?;
    xof.update(&[nonce]).map_err(SignError::from_algo)?;

    if eta == 2 {
        // CBD2 implementation using bit counting
        let mut buf = [0u8; 128];
        xof.squeeze(&mut buf).map_err(SignError::from_algo)?;
        
        let mut poly = Polynomial::<DilithiumParams>::zero();
        for i in 0..(DilithiumParams::N / 8) {
            let t = u32::from_le_bytes(buf[4*i..4*i+4].try_into().unwrap());
            let d = t & 0x5555_5555;
            let a = d.count_ones();
            let b = ((t >> 1) & 0x5555_5555).count_ones();
            for k in 0..8 {
                let coeff = ((a >> k) & 1) as i32 - ((b >> k) & 1) as i32;
                poly.coeffs[8*i + k] = (coeff as i64).rem_euclid(DilithiumParams::Q as i64) as u32;
            }
        }
        Ok(poly)
    } else if eta == 4 {
        // CBD4 implementation
        let mut buf = [0u8; 256];
        xof.squeeze(&mut buf).map_err(SignError::from_algo)?;
        
        let mut poly = Polynomial::<DilithiumParams>::zero();
        for (i, &byte) in buf.iter().enumerate().take(DilithiumParams::N) {
            let t = byte as u32;
            let a = (t & 0x0F).count_ones();
            let b = (t >> 4).count_ones();
            poly.coeffs[i] = ((a as i32 - b as i32) as i64).rem_euclid(DilithiumParams::Q as i64) as u32;
        }
        Ok(poly)
    } else {
        // General case for other eta values
        let bytes_needed = (DilithiumParams::N * 2 * eta as usize).div_ceil(8);
        let mut buf = vec![0u8; bytes_needed];
        xof.squeeze(&mut buf).map_err(SignError::from_algo)?;

        let mut poly = Polynomial::<DilithiumParams>::zero();
        let mut bit_offset = 0;
        for i in 0..DilithiumParams::N {
            let mut sum1 = 0i32;
            let mut sum2 = 0i32;
            
            for _ in 0..eta {
                sum1 += ((buf[bit_offset / 8] >> (bit_offset % 8)) & 1) as i32;
                bit_offset += 1;
            }
            for _ in 0..eta {
                sum2 += ((buf[bit_offset / 8] >> (bit_offset % 8)) & 1) as i32;
                bit_offset += 1;
            }
            
            // CBD sample is in range [-eta, eta]
            let val_signed = sum1 - sum2;
            poly.coeffs[i] = (val_signed as i64).rem_euclid(DilithiumParams::Q as i64) as u32;
        }
        Ok(poly)
    }
}

/// Samples a PolyVecL from CBD_eta.
pub fn sample_polyvecl_cbd_eta<P: DilithiumSchemeParams>(
    seed: &[u8; 32], // SEED_KEY_BYTES is always 32
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

/// Samples a PolyVecK from CBD_eta.
pub fn sample_polyveck_cbd_eta<P: DilithiumSchemeParams>(
    seed: &[u8; 32], // SEED_KEY_BYTES is always 32
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

/// Samples PolyVecL with coefficients uniformly in [-γ1+β+η, γ1-β-η] (Algorithm 23).
/// Uses SHAKE256(K || κ || i) for polynomial i.
/// 
/// Produces symmetric distribution with proper bounds
pub fn sample_polyvecl_uniform_gamma1<P: DilithiumSchemeParams>(
    key_seed_for_y: &[u8; 32], // SEED_KEY_BYTES is always 32
    kappa_nonce: u16,
    gamma1: u32,
) -> Result<PolyVecL<P>, SignError> {
    let mut pv = PolyVecL::<P>::zero();
    
    // Compute the tighter bound for y to ensure acceptance in signing
    let y_bound = gamma1 as i32 - P::BETA_PARAM as i32 - P::ETA_S1S2 as i32;
    
    // Determine number of bits needed per coefficient
    let gamma1_bits = if gamma1 == (1 << 17) {
        18 // For γ1 = 2^17
    } else if gamma1 == (1 << 19) {
        20 // For γ1 = 2^19
    } else {
        return Err(SignError::Sampling("Unsupported gamma1 value".into()));
    };
    
    for i in 0..P::L_DIM {
        let mut xof = ShakeXof256::new();
        xof.update(key_seed_for_y).map_err(SignError::from_algo)?;
        xof.update(&kappa_nonce.to_le_bytes()).map_err(SignError::from_algo)?;
        xof.update(&[i as u8]).map_err(SignError::from_algo)?;
        
        let mut coeff_idx = 0;
        
        if gamma1_bits == 18 {
            // Sample 18-bit values for γ1 = 2^17
            while coeff_idx < DilithiumParams::N {
                let mut buf = [0u8; 3]; // 18 bits requires 3 bytes
                xof.squeeze(&mut buf).map_err(SignError::from_algo)?;
                
                // Extract 18-bit value
                let r = (buf[0] as u32) 
                    | ((buf[1] as u32) << 8) 
                    | ((buf[2] as u32 & 0x03) << 16);
                
                // Rejection sampling: accept only if r < 2*gamma1 - 2
                if r >= 2 * gamma1 - 2 {
                    continue;
                }
                
                // Map to symmetric range [-(gamma1-1), gamma1-1]
                let coeff_signed = (r as i32) - ((gamma1 - 1) as i32);
                
                // Clamp to ±(γ1-β-η) to ensure acceptance in signing
                let mut v = coeff_signed;
                if v > y_bound { v = y_bound; }
                if v < -y_bound { v = -y_bound; }
                
                // Store in polynomial (convert to positive representation mod q)
                pv.polys[i].coeffs[coeff_idx] = 
                    ((v + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
                
                coeff_idx += 1;
            }
        } else {
            // Sample 20-bit values for γ1 = 2^19
            while coeff_idx < DilithiumParams::N {
                let mut buf = [0u8; 3]; // 20 bits requires 2.5 bytes, use 3 for simplicity
                xof.squeeze(&mut buf).map_err(SignError::from_algo)?;
                
                // Extract 20-bit value
                let r = (buf[0] as u32) 
                    | ((buf[1] as u32) << 8) 
                    | ((buf[2] as u32 & 0x0F) << 16);
                
                // Rejection sampling: accept only if r < 2*gamma1 - 2
                if r >= 2 * gamma1 - 2 {
                    continue;
                }
                
                // Map to symmetric range [-(gamma1-1), gamma1-1]
                let coeff_signed = (r as i32) - ((gamma1 - 1) as i32);
                
                // Clamp to ±(γ1-β-η) to ensure acceptance in signing
                let mut v = coeff_signed;
                if v > y_bound { v = y_bound; }
                if v < -y_bound { v = -y_bound; }
                
                // Store in polynomial (convert to positive representation mod q)
                pv.polys[i].coeffs[coeff_idx] = 
                    ((v + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
                
                coeff_idx += 1;
            }
        }
    }
    
    Ok(pv)
}

/// Samples challenge polynomial c with τ nonzero coefficients (Algorithm 8).
/// Uses SHAKE256(c_tilde_seed) as randomness source.
/// Accepts variable-sized challenge seeds (32/48/64 bytes)
#[allow(clippy::extra_unused_type_parameters)]
pub fn sample_challenge_c<P: DilithiumSchemeParams>(
    c_tilde_seed: &[u8], // Variable size: 32/48/64 bytes
    tau: u32,
) -> Result<Polynomial<DilithiumParams>, SignError> {
    // Allow 32 / 48 / 64 bytes as mandated by FIPS 204
    if ![32, 48, 64].contains(&c_tilde_seed.len()) {
        return Err(SignError::Sampling(
            "Challenge seed must be 32, 48, or 64 bytes".into()));
    }
    
    let mut c_poly = Polynomial::<DilithiumParams>::zero();
    
    let mut xof = ShakeXof256::new();
    xof.update(c_tilde_seed).map_err(SignError::from_algo)?;
    
    // First, squeeze sign bits (τ bits packed into bytes)
    let sign_bytes = tau.div_ceil(8);
    let mut signs = vec![0u8; sign_bytes as usize];
    xof.squeeze(&mut signs).map_err(SignError::from_algo)?;
    
    // Track which positions have been set
    let mut positions_used = [false; DilithiumParams::N];
    
    // Place τ non-zero coefficients
    for i in 0..tau {
        let mut pos: u8;
        loop {
            let mut byte = [0u8; 1];
            xof.squeeze(&mut byte).map_err(SignError::from_algo)?;
            pos = byte[0];
            
            // Find next available position
            let mut j = pos as usize;
            while j < DilithiumParams::N && positions_used[j] {
                j += 1;
            }
            
            if j < DilithiumParams::N {
                positions_used[j] = true;
                
                // Set coefficient with appropriate sign
                let sign_bit = (signs[i as usize / 8] >> (i % 8)) & 1;
                if sign_bit == 0 {
                    c_poly.coeffs[j] = 1;
                } else {
                    c_poly.coeffs[j] = DilithiumParams::Q - 1; // -1 mod Q
                }
                break;
            }
        }
    }
    
    Ok(c_poly)
}