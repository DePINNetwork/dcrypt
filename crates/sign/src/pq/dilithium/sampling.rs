//! Sampling functions for Dilithium implementing FIPS 203 algorithms.

use algorithms::poly::polynomial::Polynomial;
use algorithms::poly::params::{DilithiumParams, Modulus};
use super::polyvec::{PolyVecL, PolyVecK};
use params::pqc::dilithium::DilithiumParams as DilithiumSignParams;
use algorithms::xof::shake::ShakeXof256;
use algorithms::xof::ExtendableOutputFunction;
use crate::error::{Error as SignError};

/// Samples a polynomial with coefficients from CBD_eta (Algorithm 22).
/// Uses SHAKE256(seed || nonce) as randomness source.
pub fn sample_poly_cbd_eta<P: DilithiumSignParams>(
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

    // Each coefficient requires 2*eta bits
    let bytes_needed = if eta == 2 {
        136 // For eta=2: 256 coeffs * 4 bits / 8 = 128 bytes, but SHAKE blocks are 136
    } else if eta == 4 {
        256 // For eta=4: 256 coeffs * 8 bits / 8 = 256 bytes
    } else {
        (DilithiumParams::N * 2 * eta as usize + 7) / 8
    };
    
    let mut buf = vec![0u8; bytes_needed];
    xof.squeeze(&mut buf).map_err(SignError::from_algo)?;

    let mut poly = Polynomial::<DilithiumParams>::zero();
    
    if eta == 2 {
        // Optimized for eta=2
        for i in 0..DilithiumParams::N / 2 {
            let t = buf[i] as u32;
            let d = t & 0x0F;
            let e = t >> 4;
            
            let a = d.count_ones();
            let b = e.count_ones();
            poly.coeffs[2 * i] = ((a as i32 - b as i32 + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
            
            let a = (d >> 2).count_ones();
            let b = (e >> 2).count_ones();
            poly.coeffs[2 * i + 1] = ((a as i32 - b as i32 + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
        }
    } else if eta == 4 {
        // Optimized for eta=4
        for i in 0..DilithiumParams::N {
            let t = buf[i] as u32;
            let a = (t & 0x0F).count_ones();
            let b = (t >> 4).count_ones();
            poly.coeffs[i] = ((a as i32 - b as i32 + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
        }
    } else {
        // General case
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
            
            let val_signed = sum1 - sum2;
            poly.coeffs[i] = ((val_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
        }
    }
    
    Ok(poly)
}

/// Samples a PolyVecL from CBD_eta.
pub fn sample_polyvecl_cbd_eta<P: DilithiumSignParams>(
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
pub fn sample_polyveck_cbd_eta<P: DilithiumSignParams>(
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

/// Samples PolyVecL with coefficients uniformly in [-γ1+1, γ1-1] (Algorithm 23).
/// Uses SHAKE256(K || κ || i) for polynomial i.
pub fn sample_polyvecl_uniform_gamma1<P: DilithiumSignParams>(
    key_seed_for_y: &[u8; 32], // SEED_KEY_BYTES is always 32
    kappa_nonce: u16,
    gamma1: u32,
) -> Result<PolyVecL<P>, SignError> {
    let mut pv = PolyVecL::<P>::zero();
    
    // Determine number of bytes needed per coefficient
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
        
        if gamma1_bits == 18 {
            // Sample 18-bit values for γ1 = 2^17
            let mut buf = [0u8; 576]; // 256 * 18 / 8 = 576
            xof.squeeze(&mut buf).map_err(SignError::from_algo)?;
            
            for j in 0..DilithiumParams::N / 4 {
                let base = j * 9; // 4 coeffs * 18 bits = 72 bits = 9 bytes
                
                // Unpack 4 18-bit values from 9 bytes
                let mut z = [0u32; 4];
                z[0] = buf[base] as u32 | ((buf[base + 1] as u32) << 8) | ((buf[base + 2] as u32 & 0x03) << 16);
                z[1] = ((buf[base + 2] as u32) >> 2) | ((buf[base + 3] as u32) << 6) | ((buf[base + 4] as u32 & 0x0F) << 14);
                z[2] = ((buf[base + 4] as u32) >> 4) | ((buf[base + 5] as u32) << 4) | ((buf[base + 6] as u32 & 0x3F) << 12);
                z[3] = ((buf[base + 6] as u32) >> 6) | ((buf[base + 7] as u32) << 2) | ((buf[base + 8] as u32) << 10);
                
                for k in 0..4 {
                    let coeff_signed = (gamma1 - 1) as i32 - z[k] as i32;
                    pv.polys[i].coeffs[4 * j + k] = ((coeff_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
                }
            }
        } else {
            // Sample 20-bit values for γ1 = 2^19
            let mut buf = [0u8; 640]; // 256 * 20 / 8 = 640
            xof.squeeze(&mut buf).map_err(SignError::from_algo)?;
            
            for j in 0..DilithiumParams::N / 2 {
                let base = j * 5; // 2 coeffs * 20 bits = 40 bits = 5 bytes
                
                // Unpack 2 20-bit values from 5 bytes
                let z0 = buf[base] as u32 | ((buf[base + 1] as u32) << 8) | ((buf[base + 2] as u32 & 0x0F) << 16);
                let z1 = ((buf[base + 2] as u32) >> 4) | ((buf[base + 3] as u32) << 4) | ((buf[base + 4] as u32) << 12);
                
                let coeff0_signed = (gamma1 - 1) as i32 - z0 as i32;
                let coeff1_signed = (gamma1 - 1) as i32 - z1 as i32;
                
                pv.polys[i].coeffs[2 * j] = ((coeff0_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
                pv.polys[i].coeffs[2 * j + 1] = ((coeff1_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
            }
        }
    }
    
    Ok(pv)
}

/// Samples challenge polynomial c with τ nonzero coefficients (Algorithm 8).
/// Uses SHAKE256(c_tilde_seed) as randomness source.
pub fn sample_challenge_c<P: DilithiumSignParams>(
    c_tilde_seed: &[u8; 32], // SEED_C_TILDE_BYTES is always 32
    tau: u32,
) -> Result<Polynomial<DilithiumParams>, SignError> {
    let mut c_poly = Polynomial::<DilithiumParams>::zero();
    
    let mut xof = ShakeXof256::new();
    xof.update(c_tilde_seed).map_err(SignError::from_algo)?;
    
    // First, squeeze sign bits (τ bits packed into bytes)
    let sign_bytes = (tau + 7) / 8;
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