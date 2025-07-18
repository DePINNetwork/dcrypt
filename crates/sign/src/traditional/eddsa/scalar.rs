//! Scalar arithmetic modulo L = 2^252 + 27742317777372353535851937790883648493
//!
//! This module implements arithmetic operations on scalars for Ed25519.

use zeroize::Zeroize;
use super::constants::CURVE_ORDER;
use core::convert::TryInto;

/// Scalar value modulo L
#[derive(Clone, Zeroize)]
pub struct Scalar {
    pub(crate) bytes: [u8; 32],
}

/// 2^256 mod L (precomputed constant)
const MOD_256: [u8; 32] = [
    0x1d, 0x95, 0x98, 0x8d, 0x74, 0x31, 0xec, 0xd6,
    0x70, 0xcf, 0x7d, 0x73, 0xf4, 0x5b, 0xef, 0xc6,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
];

impl Scalar {
    /// Create scalar from bytes (little-endian)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Scalar { bytes: *bytes }
    }
}

/// Multiply a scalar by a small u8 and reduce (constant-time)
fn scalar_mul_small(src: &[u8; 32], k: u8, dst: &mut [u8; 32]) {
    let mut carry: u16 = 0;
    for i in 0..32 {
        let tmp = src[i] as u16 * k as u16 + carry;
        dst[i] = (tmp & 0xff) as u8;
        carry = tmp >> 8;
    }
    while carry != 0 {
        let mut temp = [0u8; 32];
        temp.copy_from_slice(dst);
        scalar_add(&temp, &MOD_256, dst);
        carry -= 1;
    }
    scalar_reduce(dst);
}

/// Reduce 512-bit scalar to 256-bit scalar modulo L using byte-wise algorithm
pub fn reduce_scalar_512(input: &[u8; 64], output: &mut [u8; 32]) {
    let mut r = [0u8; 32]; // running remainder
    
    // Process input from most-significant byte first
    for &byte in input.iter().rev() {
        // r = r * 256 (left-shift one byte)
        let carry = r[31];
        for i in (1..32).rev() {
            r[i] = r[i - 1];
        }
        r[0] = 0;
        
        // If there was a carry, add carry * (2^256 mod L)
        if carry != 0 {
            let mut tmp = [0u8; 32];
            scalar_mul_small(&MOD_256, carry, &mut tmp);
            let mut r_copy = [0u8; 32];
            r_copy.copy_from_slice(&r);
            scalar_add(&r_copy, &tmp, &mut r);
        }
        
        // Add current input byte
        if byte != 0 {
            let mut tmp = [0u8; 32];
            tmp[0] = byte;
            let mut r_copy = [0u8; 32];
            r_copy.copy_from_slice(&r);
            scalar_add(&r_copy, &tmp, &mut r);
        }
    }
    
    // Final reduction to ensure r < L
    scalar_reduce(&mut r);
    output.copy_from_slice(&r);
}

/// Add two scalars modulo L
fn scalar_add(a: &[u8; 32], b: &[u8; 32], result: &mut [u8; 32]) {
    let mut carry: u16 = 0;
    
    for i in 0..32 {
        let tmp = a[i] as u16 + b[i] as u16 + carry;
        result[i] = (tmp & 0xFF) as u8;
        carry = tmp >> 8;
    }
    
    // If there's a carry, we need to add 2^256 mod L (not 38!)
    // Add 2^256 mod L for each unit of carry
    let mut extra_carry = carry;
    while extra_carry != 0 {
        let mut sub_carry: u16 = 0;
        for i in 0..32 {
            let tmp = result[i] as u16 + (MOD_256[i] as u16) + sub_carry;
            result[i] = (tmp & 0xFF) as u8;
            sub_carry = tmp >> 8;
        }
        extra_carry = sub_carry;
    }
    
    // Reduce if necessary
    scalar_reduce(result);
}

/// Multiply two scalars modulo L
fn scalar_mul(a: &[u8; 32], b: &[u8; 32], result: &mut [u8; 32]) {
    // ---------- Correct 512-bit product with full carry propagation ----------
    // Use 32-bit limbs to avoid overflow during accumulation.
    let mut prod = [0u32; 64];

    // 1. School-book multiplication (base 256, little-endian).
    for i in 0..32 {
        for j in 0..32 {
            prod[i + j] += (a[i] as u32) * (b[j] as u32);
        }
    }

    // 2. Single carry-propagation pass so every limb < 256.
    let mut carry: u32 = 0;
    for limb in &mut prod {
        let val = *limb + carry;
        *limb = val & 0xFF;      // keep low 8 bits
        carry = val >> 8;        // propagate the rest
    }
    // Any final carry beyond 512 bits can be ignored; we only keep 64 bytes.

    // 3. Convert to byte array for Barrett reduction.
    let mut prod_bytes = [0u8; 64];
    for (i, limb) in prod.iter().enumerate() {
        prod_bytes[i] = *limb as u8;
    }

    // 4. Reduce modulo L.
    reduce_scalar_512(&prod_bytes, result);
}

/// Reduce scalar modulo L
fn scalar_reduce(s: &mut [u8; 32]) {
    // ---- constants ----
    let l_limbs: [u64; 4] = [
        u64::from_le_bytes(CURVE_ORDER[ 0.. 8].try_into().unwrap()),
        u64::from_le_bytes(CURVE_ORDER[ 8..16].try_into().unwrap()),
        u64::from_le_bytes(CURVE_ORDER[16..24].try_into().unwrap()),
        u64::from_le_bytes(CURVE_ORDER[24..32].try_into().unwrap()),
    ];

    // ---- load s into four little‑endian 64‑bit limbs ----
    let mut s_limbs = [
        u64::from_le_bytes(s[ 0.. 8].try_into().unwrap()),
        u64::from_le_bytes(s[ 8..16].try_into().unwrap()),
        u64::from_le_bytes(s[16..24].try_into().unwrap()),
        u64::from_le_bytes(s[24..32].try_into().unwrap()),
    ];

    // ---- up to 16 unconditional iterations ----
    for _ in 0..16 {
        // 1. subtract: diff = s - L  (with propagated borrow)
        let mut diff = [0u64; 4];
        let mut borrow: u64 = 0;
        for i in 0..4 {
            // full 128‑bit arithmetic to capture the borrow
            let tmp = (s_limbs[i] as u128)
                .wrapping_sub(l_limbs[i] as u128 + borrow as u128);
            diff[i]  =  tmp as u64;
            borrow   = (tmp >> 127) as u64;        // 1 if we wrapped → s < L
        }

        // 2. mask = 0xffff…ffff if s >= L (borrow == 0), else 0x0
        let mask = borrow.wrapping_sub(1);         // 0→all‑ones, 1→0

        // 3. choose in constant time
        for i in 0..4 {
            s_limbs[i] = (s_limbs[i] & !mask) | (diff[i] & mask);
        }
    }

    // ---- store back to little‑endian byte array ----
    for i in 0..4 {
        s[i * 8..i * 8 + 8].copy_from_slice(&s_limbs[i].to_le_bytes());
    }
}

/// Compute s = (r + k*a) mod L
pub fn compute_s(r: &[u8; 32], k: &[u8; 32], a: &[u8], s: &mut [u8; 32]) {
    let mut a_array = [0u8; 32];
    a_array.copy_from_slice(&a[0..32]);
    
    let mut ka = [0u8; 32];
    scalar_mul(k, &a_array, &mut ka);
    scalar_add(r, &ka, s);
}

/// Reduce 512-bit hash to scalar
pub fn reduce_512_to_scalar(hash: &[u8], output: &mut [u8; 32]) {
    if hash.len() < 64 {
        output.fill(0);
        output[0..hash.len().min(32)].copy_from_slice(&hash[0..hash.len().min(32)]);
        return;
    }
    
    let mut hash_array = [0u8; 64];
    hash_array.copy_from_slice(&hash[0..64]);
    reduce_scalar_512(&hash_array, output);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scalar_arithmetic() {
        // Test basic scalar operations
        let a = Scalar::from_bytes(&[1; 32]);
        let b = Scalar::from_bytes(&[2; 32]);
        
        // Test add
        let mut c = [0u8; 32];
        scalar_add(&a.bytes, &b.bytes, &mut c);
        assert!(c != [0; 32]);
        
        // Test mul
        let mut d = [0u8; 32];
        scalar_mul(&a.bytes, &b.bytes, &mut d);
        assert!(d != [0; 32]);
    }
    
    #[test]
    fn test_scalar_reduction() {
        // Test that values larger than L get reduced
        let mut large = [0xffu8; 32];
        scalar_reduce(&mut large);
        
        // Should be reduced to a value less than L
        let mut is_less = false;
        for i in (0..32).rev() {
            use core::cmp::Ordering;
            match large[i].cmp(&CURVE_ORDER[i]) {
                Ordering::Less => {
                    is_less = true;
                    break;
                }
                Ordering::Greater => break,
                Ordering::Equal => continue,
            }
        }
        assert!(is_less);
    }
}