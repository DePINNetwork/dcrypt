//! P-192 scalar arithmetic operations

use crate::ec::p192::constants::{P192_SCALAR_SIZE, bytes_to_limbs_le, limbs_to_bytes_be};
use crate::error::{Error, Result, validate};
use common::security::{SecretBuffer, SecureOperation, SecureCompare};
use zeroize::{Zeroize, ZeroizeOnDrop};
use params::traditional::ecdsa::NIST_P192;

/// P-192 scalar: integers mod n, where
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF (curve order).
#[derive(Clone, Zeroize, ZeroizeOnDrop, Debug)]
pub struct Scalar(SecretBuffer<P192_SCALAR_SIZE>);

impl Scalar {
    /// Create a scalar from raw bytes with reduction mod n.
    /// Ensures result ∈ [1, n−1]. Errors if result = 0.
    pub fn new(mut data: [u8; P192_SCALAR_SIZE]) -> Result<Self> {
        Self::reduce_scalar_bytes(&mut data)?;
        Ok(Scalar(SecretBuffer::new(data)))
    }

    /// Internal constructor without checking zero
    fn from_bytes_unchecked(bytes: [u8; P192_SCALAR_SIZE]) -> Self {
        Scalar(SecretBuffer::new(bytes))
    }

    /// Create from existing SecretBuffer (applies reduction & zero check)
    pub fn from_secret_buffer(buffer: SecretBuffer<P192_SCALAR_SIZE>) -> Result<Self> {
        let mut tmp = [0u8; P192_SCALAR_SIZE];
        tmp.copy_from_slice(buffer.as_ref());
        Self::new(tmp)
    }

    /// Access the underlying SecretBuffer
    pub fn as_secret_buffer(&self) -> &SecretBuffer<P192_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize to big‐endian bytes
    pub fn serialize(&self) -> [u8; P192_SCALAR_SIZE] {
        let mut out = [0u8; P192_SCALAR_SIZE];
        out.copy_from_slice(self.0.as_ref());
        out
    }

    /// Deserialize from bytes (with validation)
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        validate::length("P-192 Scalar", bytes.len(), P192_SCALAR_SIZE)?;
        let mut tmp = [0u8; P192_SCALAR_SIZE];
        tmp.copy_from_slice(bytes);
        Self::new(tmp)
    }

    /// Is this scalar zero?
    pub fn is_zero(&self) -> bool {
        self.0.as_ref().iter().all(|&b| b == 0)
    }

    /// Convert big‐endian bytes → little‐endian 6 u32 limbs
    #[inline(always)]
    fn to_le_limbs(bytes_be: &[u8; 24]) -> [u32; 6] {
        let mut limbs = [0u32; 6];
        for i in 0..6 {
            let offset = (5 - i) * 4; // Start from the end for LE
            limbs[i] = u32::from_be_bytes([
                bytes_be[offset],
                bytes_be[offset + 1],
                bytes_be[offset + 2],
                bytes_be[offset + 3],
            ]);
        }
        limbs
    }

    /// Convert little‐endian 6‐limb → big‐endian bytes
    #[inline(always)]
    fn limbs_to_be(limbs: &[u32; 6]) -> [u8; 24] {
        let mut out = [0u8; 24];
        for i in 0..6 {
            let b = limbs[i].to_be_bytes();
            let offset = (5 - i) * 4;
            out[offset..offset + 4].copy_from_slice(&b);
        }
        out
    }

    /// Add two scalars mod n
    pub fn add_mod_n(&self, other: &Self) -> Result<Self> {
        let a_limbs = Self::to_le_limbs(&self.serialize());
        let b_limbs = Self::to_le_limbs(&other.serialize());
        let mut r = [0u32; 6];
        let mut carry: u64 = 0;
        for i in 0..6 {
            let tmp = a_limbs[i] as u64 + b_limbs[i] as u64 + carry;
            r[i] = tmp as u32;
            carry = tmp >> 32;
        }
        // If overflow OR r ≥ n, subtract n
        if carry == 1 || Self::geq(&r, &Self::N_LIMBS) {
            Self::sub_in_place(&mut r, &Self::N_LIMBS);
        }
        Ok(Self::from_bytes_unchecked(Self::limbs_to_be(&r)))
    }

    /// Subtract two scalars mod n
    pub fn sub_mod_n(&self, other: &Self) -> Result<Self> {
        let a_limbs = Self::to_le_limbs(&self.serialize());
        let b_limbs = Self::to_le_limbs(&other.serialize());
        let mut r = [0u32; 6];
        let mut borrow: i64 = 0;
        for i in 0..6 {
            let tmp = a_limbs[i] as i64 - b_limbs[i] as i64 - borrow;
            if tmp < 0 {
                r[i] = (tmp + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                r[i] = tmp as u32;
                borrow = 0;
            }
        }
        if borrow == 1 {
            // Add n back
            let mut c: u64 = 0;
            for i in 0..6 {
                let tmp = r[i] as u64 + Self::N_LIMBS[i] as u64 + c;
                r[i] = tmp as u32;
                c = tmp >> 32;
            }
        }
        Ok(Self::from_bytes_unchecked(Self::limbs_to_be(&r)))
    }

    /// Multiply two scalars mod n (double‐and‐add)
    pub fn mul_mod_n(&self, other: &Self) -> Result<Self> {
        let mut acc = Self::from_bytes_unchecked([0u8; 24]);
        let self_val = self.clone();
        
        for &byte in other.serialize().iter() {
            for i in (0..8).rev() {
                acc = acc.add_mod_n(&acc)?; // Double
                if ((byte >> i) & 1) == 1 {
                    acc = acc.add_mod_n(&self_val)?; // Add
                }
            }
        }
        Ok(acc)
    }

    /// Compute inverse mod n via Fermat (n − 2)
    pub fn inv_mod_n(&self) -> Result<Self> {
        if self.is_zero() {
            return Err(Error::param("P-192 Scalar", "Inverse of zero"));
        }
        
        // P-192 curve order n = FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
        // n-2 = FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D2282F
        const N_MINUS_2: [u8; 24] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0x99, 0xDE, 0xF8, 0x36,
            0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x2F,
        ];
        
        // Binary exponentiation
        let mut result = {
            let mut one = [0u8; 24];
            one[23] = 1;
            Scalar::from_bytes_unchecked(one)
        };
        let base = self.clone();
        
        for &byte in N_MINUS_2.iter() {
            for i in (0..8).rev() {
                result = result.mul_mod_n(&result)?; // Square
                if ((byte >> i) & 1) == 1 {
                    result = result.mul_mod_n(&base)?; // Multiply
                }
            }
        }
        
        Ok(result)
    }

    /// Negate mod n: (n - self) if ≠ 0
    pub fn negate(&self) -> Self {
        if self.is_zero() {
            return Self::from_bytes_unchecked([0u8; 24]);
        }
        let a_limbs = Self::to_le_limbs(&self.serialize());
        let mut r = [0u32; 6];
        let n = Self::N_LIMBS;
        let mut borrow: i64 = 0;
        for i in 0..6 {
            let tmp = n[i] as i64 - a_limbs[i] as i64 - borrow;
            if tmp < 0 {
                r[i] = (tmp + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                r[i] = tmp as u32;
                borrow = 0;
            }
        }
        Self::from_bytes_unchecked(Self::limbs_to_be(&r))
    }

    /// Internal helper: reduce raw bytes mod n, ensure ≠ 0
    fn reduce_scalar_bytes(bytes: &mut [u8; 24]) -> Result<()> {
        let order = &NIST_P192.n;
        // reject zero
        if bytes.iter().all(|&b| b == 0) {
            return Err(Error::param("P-192 Scalar", "Scalar cannot be zero"));
        }
        // compare bytes vs order big‐endian
        let mut gt = 0u8;
        let mut lt = 0u8;
        for i in 0..24 {
            let x = bytes[i];
            let y = order[i];
            gt |= ((x > y) as u8) & (!lt);
            lt |= ((x < y) as u8) & (!gt);
        }
        // if ≥ order, subtract order
        if gt == 1 || (lt == 0 && gt == 0) {
            let mut borrow = 0u16;
            for i in (0..24).rev() {
                let v = (bytes[i] as i16) - (order[i] as i16) - (borrow as i16);
                if v < 0 {
                    bytes[i] = (v + 256) as u8;
                    borrow = 1;
                } else {
                    bytes[i] = v as u8;
                    borrow = 0;
                }
            }
        }
        // ensure not zero after reduction
        if bytes.iter().all(|&b| b == 0) {
            return Err(Error::param("P-192 Scalar", "Reduction resulted in zero"));
        }
        Ok(())
    }

    /// Compare two 6‐limb arrays: a ≥ b ?
    #[inline(always)]
    fn geq(a: &[u32; 6], b: &[u32; 6]) -> bool {
        for i in (0..6).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true
    }

    /// Subtract b from a in‐place, ignoring final borrow
    #[inline(always)]
    fn sub_in_place(a: &mut [u32; 6], b: &[u32; 6]) {
        let mut borrow = 0u64;
        for i in 0..6 {
            let tmp = (a[i] as u64)
                .wrapping_sub(b[i] as u64)
                .wrapping_sub(borrow);
            a[i] = tmp as u32;
            borrow = (tmp >> 63) & 1;
        }
    }

    /// Order n in little‐endian limbs
    /// n = FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
    const N_LIMBS: [u32; 6] = [
        0xB4D22831, // least significant 32 bits
        0x146BC9B1,
        0x99DEF836,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF, // most significant
    ];
}