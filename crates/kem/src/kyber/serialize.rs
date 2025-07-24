// kem/src/kyber/serialize.rs

//! Serialization functions for Kyber data structures.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use dcrypt_algorithms::error::{Error as AlgoError, Result as AlgoResult};
use dcrypt_algorithms::poly::params::Modulus;
use dcrypt_algorithms::poly::polynomial::Polynomial;

use super::cpa_pke::{CpaCiphertextInner, CpaPublicKeyInner, CpaSecretKeyInner};
use super::params::{KyberParams, KyberPolyModParams, KYBER_RHO_SEED_BYTES};
use super::polyvec::PolyVec;

// Constants for compression bit sizes
const KYBER_D4_VALS_PER_BYTE: usize = 2;
const KYBER_D5_VALS_PER_CHUNK: usize = 8;
const KYBER_D5_BYTES_PER_CHUNK: usize = 5;
const KYBER_D10_VALS_PER_CHUNK: usize = 4;
const KYBER_D10_BYTES_PER_CHUNK: usize = 5;
const KYBER_D11_VALS_PER_CHUNK: usize = 8;
const KYBER_D11_BYTES_PER_CHUNK: usize = 11;

// Constants for packing
const KYBER_POLYVEC_PACKED_BITS: usize = 12; // Bits per coefficient in packed form

/// Pack a polynomial with compression
fn compress_poly(poly: &Polynomial<KyberPolyModParams>, d: usize) -> Vec<u8> {
    let mut result = Vec::new();

    if d == 4 {
        // Pack 4-bit values, 2 per byte
        for chunk in poly.as_coeffs_slice().chunks(KYBER_D4_VALS_PER_BYTE) {
            let c0 = compress_coeff(chunk[0], d) as u8;
            let c1 = if chunk.len() > 1 {
                compress_coeff(chunk[1], d) as u8
            } else {
                0
            };
            result.push((c0 & 0x0F) | ((c1 & 0x0F) << 4));
        }
    } else if d == 5 {
        // Pack 5-bit values, 8 values in 5 bytes
        for chunk in poly.as_coeffs_slice().chunks(KYBER_D5_VALS_PER_CHUNK) {
            let mut vals = [0u8; KYBER_D5_VALS_PER_CHUNK];
            for (i, &c) in chunk.iter().enumerate() {
                vals[i] = compress_coeff(c, d) as u8;
            }

            result.push(vals[0] | (vals[1] << 5));
            result.push((vals[1] >> 3) | (vals[2] << 2) | (vals[3] << 7));
            result.push((vals[3] >> 1) | (vals[4] << 4));
            result.push((vals[4] >> 4) | (vals[5] << 1) | (vals[6] << 6));
            result.push((vals[6] >> 2) | (vals[7] << 3));
        }
    } else if d == 10 {
        // Pack 10-bit values, 4 values in 5 bytes
        for chunk in poly.as_coeffs_slice().chunks(KYBER_D10_VALS_PER_CHUNK) {
            let mut vals = [0u16; KYBER_D10_VALS_PER_CHUNK];
            for (i, &c) in chunk.iter().enumerate() {
                vals[i] = compress_coeff(c, d) as u16;
            }

            result.push(vals[0] as u8);
            result.push(((vals[0] >> 8) | (vals[1] << 2)) as u8);
            result.push(((vals[1] >> 6) | (vals[2] << 4)) as u8);
            result.push(((vals[2] >> 4) | (vals[3] << 6)) as u8);
            result.push((vals[3] >> 2) as u8);
        }
    } else if d == 11 {
        // Pack 11-bit values, 8 values in 11 bytes
        for chunk in poly.as_coeffs_slice().chunks(KYBER_D11_VALS_PER_CHUNK) {
            let mut vals = [0u16; KYBER_D11_VALS_PER_CHUNK];
            for (i, &c) in chunk.iter().enumerate() {
                vals[i] = compress_coeff(c, d) as u16;
            }

            result.push(vals[0] as u8);
            result.push(((vals[0] >> 8) | (vals[1] << 3)) as u8);
            result.push(((vals[1] >> 5) | (vals[2] << 6)) as u8);
            result.push((vals[2] >> 2) as u8);
            result.push(((vals[2] >> 10) | (vals[3] << 1)) as u8);
            result.push(((vals[3] >> 7) | (vals[4] << 4)) as u8);
            result.push(((vals[4] >> 4) | (vals[5] << 7)) as u8);
            result.push((vals[5] >> 1) as u8);
            result.push(((vals[5] >> 9) | (vals[6] << 2)) as u8);
            result.push(((vals[6] >> 6) | (vals[7] << 5)) as u8);
            result.push((vals[7] >> 3) as u8);
        }
    }

    result
}

/// Decompress a polynomial
fn decompress_poly(data: &[u8], d: usize) -> AlgoResult<Polynomial<KyberPolyModParams>> {
    let mut poly = Polynomial::<KyberPolyModParams>::zero();
    let mut byte_idx = 0;
    let mut coeff_idx = 0;

    if d == 4 {
        // Unpack 4-bit values, 2 per byte
        while coeff_idx < KyberPolyModParams::N && byte_idx < data.len() {
            let byte = data[byte_idx];
            poly.coeffs[coeff_idx] = decompress_coeff((byte & 0x0F) as u32, d);
            coeff_idx += 1;
            if coeff_idx < KyberPolyModParams::N {
                poly.coeffs[coeff_idx] = decompress_coeff((byte >> 4) as u32, d);
                coeff_idx += 1;
            }
            byte_idx += 1;
        }
    } else if d == 5 {
        // Unpack 5-bit values, 8 values from 5 bytes
        while coeff_idx < KyberPolyModParams::N && byte_idx + KYBER_D5_BYTES_PER_CHUNK <= data.len()
        {
            let b = &data[byte_idx..byte_idx + KYBER_D5_BYTES_PER_CHUNK];
            poly.coeffs[coeff_idx] = decompress_coeff((b[0] & 0x1F) as u32, d);
            poly.coeffs[coeff_idx + 1] =
                decompress_coeff(((b[0] >> 5) | ((b[1] & 0x03) << 3)) as u32, d);
            poly.coeffs[coeff_idx + 2] = decompress_coeff(((b[1] >> 2) & 0x1F) as u32, d);
            poly.coeffs[coeff_idx + 3] =
                decompress_coeff(((b[1] >> 7) | ((b[2] & 0x0F) << 1)) as u32, d);
            poly.coeffs[coeff_idx + 4] =
                decompress_coeff(((b[2] >> 4) | ((b[3] & 0x01) << 4)) as u32, d);
            poly.coeffs[coeff_idx + 5] = decompress_coeff(((b[3] >> 1) & 0x1F) as u32, d);
            poly.coeffs[coeff_idx + 6] =
                decompress_coeff(((b[3] >> 6) | ((b[4] & 0x07) << 2)) as u32, d);
            poly.coeffs[coeff_idx + 7] = decompress_coeff((b[4] >> 3) as u32, d);
            coeff_idx += KYBER_D5_VALS_PER_CHUNK;
            byte_idx += KYBER_D5_BYTES_PER_CHUNK;
        }
    } else if d == 10 {
        // Unpack 10-bit values, 4 values from 5 bytes
        while coeff_idx < KyberPolyModParams::N
            && byte_idx + KYBER_D10_BYTES_PER_CHUNK <= data.len()
        {
            let b = &data[byte_idx..byte_idx + KYBER_D10_BYTES_PER_CHUNK];
            poly.coeffs[coeff_idx] =
                decompress_coeff((b[0] as u32) | ((b[1] as u32 & 0x03) << 8), d);
            poly.coeffs[coeff_idx + 1] =
                decompress_coeff(((b[1] as u32) >> 2) | ((b[2] as u32 & 0x0F) << 6), d);
            poly.coeffs[coeff_idx + 2] =
                decompress_coeff(((b[2] as u32) >> 4) | ((b[3] as u32 & 0x3F) << 4), d);
            poly.coeffs[coeff_idx + 3] =
                decompress_coeff(((b[3] as u32) >> 6) | ((b[4] as u32) << 2), d);
            coeff_idx += KYBER_D10_VALS_PER_CHUNK;
            byte_idx += KYBER_D10_BYTES_PER_CHUNK;
        }
    } else if d == 11 {
        // Unpack 11-bit values, 8 values from 11 bytes
        while coeff_idx < KyberPolyModParams::N
            && byte_idx + KYBER_D11_BYTES_PER_CHUNK <= data.len()
        {
            let b = &data[byte_idx..byte_idx + KYBER_D11_BYTES_PER_CHUNK];
            poly.coeffs[coeff_idx] =
                decompress_coeff((b[0] as u32) | ((b[1] as u32 & 0x07) << 8), d);
            poly.coeffs[coeff_idx + 1] =
                decompress_coeff(((b[1] as u32) >> 3) | ((b[2] as u32 & 0x3F) << 5), d);
            poly.coeffs[coeff_idx + 2] = decompress_coeff(
                ((b[2] as u32) >> 6) | ((b[3] as u32) << 2) | ((b[4] as u32 & 0x01) << 10),
                d,
            );
            poly.coeffs[coeff_idx + 3] =
                decompress_coeff(((b[4] as u32) >> 1) | ((b[5] as u32 & 0x0F) << 7), d);
            poly.coeffs[coeff_idx + 4] =
                decompress_coeff(((b[5] as u32) >> 4) | ((b[6] as u32 & 0x7F) << 4), d);
            poly.coeffs[coeff_idx + 5] = decompress_coeff(
                ((b[6] as u32) >> 7) | ((b[7] as u32) << 1) | ((b[8] as u32 & 0x03) << 9),
                d,
            );
            poly.coeffs[coeff_idx + 6] =
                decompress_coeff(((b[8] as u32) >> 2) | ((b[9] as u32 & 0x1F) << 6), d);
            poly.coeffs[coeff_idx + 7] =
                decompress_coeff(((b[9] as u32) >> 5) | ((b[10] as u32) << 3), d);
            coeff_idx += KYBER_D11_VALS_PER_CHUNK;
            byte_idx += KYBER_D11_BYTES_PER_CHUNK;
        }
    }

    Ok(poly)
}

/// Compress a coefficient
fn compress_coeff(coeff: u32, d: usize) -> u32 {
    ((((coeff as u64) << d) + (KyberPolyModParams::Q as u64 / 2)) / (KyberPolyModParams::Q as u64))
        as u32
        & ((1 << d) - 1)
}

/// Decompress a coefficient
fn decompress_coeff(coeff: u32, d: usize) -> u32 {
    (((coeff as u64) * (KyberPolyModParams::Q as u64) + (1 << (d - 1))) >> d) as u32
}

/// Pack polynomial vector with compression
fn compress_polyvec<P: KyberParams>(pv: &PolyVec<P>, d: usize) -> Vec<u8> {
    let mut result = Vec::new();

    for poly in &pv.polys {
        result.extend(compress_poly(poly, d));
    }

    result
}

/// Decompress polynomial vector
fn decompress_polyvec<P: KyberParams>(data: &[u8], d: usize) -> AlgoResult<PolyVec<P>> {
    let mut pv = PolyVec::<P>::zero();
    let bytes_per_poly = (KyberPolyModParams::N * d).div_ceil(8);

    for i in 0..P::K {
        let start = i * bytes_per_poly;
        let end = start + bytes_per_poly;
        if end > data.len() {
            return Err(AlgoError::Processing {
                operation: "decompress_polyvec",
                details: "insufficient data",
            });
        }
        pv.polys[i] = decompress_poly(&data[start..end], d)?;
    }

    Ok(pv)
}

/// Calculate packed polynomial vector size in bytes
fn packed_polyvec_bytes(k: usize) -> usize {
    (k * KyberPolyModParams::N * KYBER_POLYVEC_PACKED_BITS).div_ceil(8)
}

/// Pack public key
pub fn pack_pk<P: KyberParams>(pk: &CpaPublicKeyInner<P>) -> AlgoResult<Vec<u8>> {
    let (t, rho) = pk;
    let mut packed = Vec::new();

    // Pack t (polynomial vector)
    packed.extend(t.to_bytes());

    // Append rho
    packed.extend_from_slice(rho);

    Ok(packed)
}

/// Unpack public key
pub fn unpack_pk<P: KyberParams>(bytes: &[u8]) -> AlgoResult<CpaPublicKeyInner<P>> {
    let polyvec_bytes = packed_polyvec_bytes(P::K);

    if bytes.len() < polyvec_bytes + KYBER_RHO_SEED_BYTES {
        return Err(AlgoError::Processing {
            operation: "unpack_pk",
            details: "insufficient data",
        });
    }

    // Unpack t
    let t = PolyVec::<P>::from_bytes(&bytes[..polyvec_bytes], P::K)?;

    // Extract rho
    let mut rho = [0u8; KYBER_RHO_SEED_BYTES];
    rho.copy_from_slice(&bytes[polyvec_bytes..polyvec_bytes + KYBER_RHO_SEED_BYTES]);

    Ok((t, rho))
}

/// Pack secret key
pub fn pack_sk<P: KyberParams>(sk: &CpaSecretKeyInner<P>) -> AlgoResult<Vec<u8>> {
    Ok(sk.to_bytes())
}

/// Unpack secret key
pub fn unpack_sk<P: KyberParams>(bytes: &[u8]) -> AlgoResult<CpaSecretKeyInner<P>> {
    PolyVec::<P>::from_bytes(bytes, P::K)
}

/// Pack ciphertext
pub fn pack_ciphertext<P: KyberParams>(ct: &CpaCiphertextInner<P>) -> AlgoResult<Vec<u8>> {
    let (u, v) = ct;
    let mut packed = Vec::new();

    // Compress and pack u
    packed.extend(compress_polyvec::<P>(u, P::DU));

    // Compress and pack v
    packed.extend(compress_poly(v, P::DV));

    Ok(packed)
}

/// Unpack ciphertext
pub fn unpack_ciphertext<P: KyberParams>(bytes: &[u8]) -> AlgoResult<CpaCiphertextInner<P>> {
    let u_compressed_bytes = (P::K * KyberPolyModParams::N * P::DU).div_ceil(8);
    let v_compressed_bytes = (KyberPolyModParams::N * P::DV).div_ceil(8);

    if bytes.len() < u_compressed_bytes + v_compressed_bytes {
        return Err(AlgoError::Processing {
            operation: "unpack_ciphertext",
            details: "insufficient data",
        });
    }

    // Decompress u
    let u = decompress_polyvec::<P>(&bytes[..u_compressed_bytes], P::DU)?;

    // Decompress v
    let v = decompress_poly(
        &bytes[u_compressed_bytes..u_compressed_bytes + v_compressed_bytes],
        P::DV,
    )?;

    Ok((u, v))
}
