//! Public Ed25519 operations
//!
//! This module provides the high-level operations used by the Ed25519
//! signature scheme implementation.

use super::point::{CompressedPoint, EdwardsPoint};
use super::scalar::{
    compute_s as scalar_compute_s, reduce_512_to_scalar as scalar_reduce_512, Scalar,
};
use dcrypt_internal::constant_time::ct_eq;

/// Scalar multiplication with base point
pub fn scalar_mult_base(scalar_bytes: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes(scalar_bytes);
    let point = EdwardsPoint::base_point().scalar_mult(&scalar);
    let compressed = point.compress();
    compressed.to_bytes()
}

/// Derive public key from secret scalar
pub fn derive_public_key(scalar_bytes: &[u8], output: &mut [u8; 32]) -> Result<(), &'static str> {
    if scalar_bytes.len() < 32 {
        return Err("Invalid scalar length");
    }

    let mut scalar_array = [0u8; 32];
    scalar_array.copy_from_slice(&scalar_bytes[0..32]);

    *output = scalar_mult_base(&scalar_array);
    Ok(())
}

/// Reduce 512-bit hash to scalar
pub fn reduce_512_to_scalar(hash: &[u8], output: &mut [u8; 32]) {
    scalar_reduce_512(hash, output);
}

/// Compute s = (r + k*a) mod L
pub fn compute_s(r: &[u8; 32], k: &[u8; 32], a: &[u8], s: &mut [u8; 32]) {
    scalar_compute_s(r, k, a, s);
}

/// Verify equation \[s\]B = R + \[k\]A
pub fn verify_equation(
    s_bytes: &[u8],
    r_bytes: &[u8],
    k: &[u8; 32],
    a_bytes: &[u8],
    check: &mut [u8; 32],
) -> Result<(), &'static str> {
    // Parse points
    let mut r_array = [0u8; 32];
    let mut a_array = [0u8; 32];
    r_array.copy_from_slice(&r_bytes[0..32]);
    a_array.copy_from_slice(&a_bytes[0..32]);

    let r_point = CompressedPoint::from_bytes(&r_array)
        .decompress()
        .ok_or("Invalid R point")?;

    let a_point = CompressedPoint::from_bytes(&a_array)
        .decompress()
        .ok_or("Invalid A point")?;

    // Compute \[s\]B
    let mut s_array = [0u8; 32];
    s_array.copy_from_slice(&s_bytes[0..32]);
    let s_scalar = Scalar::from_bytes(&s_array);
    let sb = EdwardsPoint::base_point().scalar_mult(&s_scalar);

    // Compute \[k\]A
    let k_scalar = Scalar::from_bytes(k);
    let ka = a_point.scalar_mult(&k_scalar);

    // Compute R + \[k\]A
    let r_plus_ka = r_point.add(&ka);

    // Compare
    let sb_compressed = sb.compress().to_bytes();
    let r_plus_ka_compressed = r_plus_ka.compress().to_bytes();

    if ct_eq(sb_compressed, r_plus_ka_compressed) {
        check.fill(1);
    } else {
        check.fill(0);
    }

    Ok(())
}
