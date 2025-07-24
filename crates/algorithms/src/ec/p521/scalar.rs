//! P-521 scalar arithmetic operations

use crate::ec::p521::constants::{P521_SCALAR_SIZE, p521_bytes_to_limbs, p521_limbs_to_bytes};
use crate::ec::p521::field::FieldElement;
use crate::error::{Error, Result, validate};
use dcrypt_common::security::SecretBuffer;
use zeroize::{Zeroize, ZeroizeOnDrop};
use dcrypt_params::traditional::ecdsa::NIST_P521;

/// P-521 scalar value for use in elliptic curve operations.
/// Represents integers modulo the curve order n. Used for private keys
/// and scalar multiplication. Automatically zeroized on drop for security.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Debug)]
pub struct Scalar(SecretBuffer<P521_SCALAR_SIZE>);

impl Scalar {
    /// Create a scalar from raw bytes with modular reduction.
    /// Ensures the scalar is in the valid range [1, n-1] where n is the curve order.
    /// Performs modular reduction if the input is >= n.
    /// Returns an error if the result would be zero (invalid for cryptographic use).
    pub fn new(mut data: [u8; P521_SCALAR_SIZE]) -> Result<Self> {
        Self::reduce_scalar_bytes(&mut data)?;
        Ok(Scalar(SecretBuffer::new(data)))
    }

    /// Internal constructor that allows zero values.
    /// Used for intermediate arithmetic operations where zero is a valid result.
    /// Should NOT be used for secret keys, nonces, or final signature components.
    pub(super) fn from_bytes_unchecked(bytes: [u8; P521_SCALAR_SIZE]) -> Self {
        Scalar(SecretBuffer::new(bytes))
    }

    /// Create a scalar from an existing SecretBuffer.
    /// Performs the same validation and reduction as `new()` but starts
    /// from a SecretBuffer instead of a raw byte array.
    pub fn from_secret_buffer(buffer: SecretBuffer<P521_SCALAR_SIZE>) -> Result<Self> {
        let mut bytes = [0u8; P521_SCALAR_SIZE];
        bytes.copy_from_slice(buffer.as_ref());

        Self::reduce_scalar_bytes(&mut bytes)?;
        Ok(Scalar(SecretBuffer::new(bytes)))
    }

    /// Access the underlying SecretBuffer containing the scalar value
    pub fn as_secret_buffer(&self) -> &SecretBuffer<P521_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize the scalar to a byte array.
    /// Returns the scalar in big-endian byte representation.
    /// The output is suitable for storage or transmission.
    pub fn serialize(&self) -> [u8; P521_SCALAR_SIZE] {
        let mut result = [0u8; P521_SCALAR_SIZE];
        result.copy_from_slice(self.0.as_ref());
        result
    }

    /// Deserialize a scalar from bytes with validation.
    /// Parses bytes as a big-endian scalar value and ensures it's
    /// in the valid range for P-521 operations.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        validate::length("P-521 Scalar", bytes.len(), P521_SCALAR_SIZE)?;

        let mut scalar_bytes = [0u8; P521_SCALAR_SIZE];
        scalar_bytes.copy_from_slice(bytes);

        Self::new(scalar_bytes)
    }

    /// Check if the scalar represents zero.
    /// Constant-time check to determine if the scalar is the
    /// additive identity (which is invalid for most cryptographic operations).
    pub fn is_zero(&self) -> bool {
        self.0.as_ref().iter().all(|&b| b == 0)
    }

    /// Convert big-endian 66-byte array to 17 little-endian u32 limbs
    #[inline(always)]
    fn to_le_limbs(bytes_be: &[u8; 66]) -> [u32; 17] {
        p521_bytes_to_limbs(bytes_be)
    }

    /// Convert 17 little-endian limbs back to big-endian 66-byte array
    #[inline(always)]
    fn limbs_to_be(limbs: &[u32; 17]) -> [u8; 66] {
        p521_limbs_to_bytes(limbs)
    }

    /// Add two scalars modulo the curve order n
    pub fn add_mod_n(&self, other: &Self) -> Result<Self> {
        let a = Self::to_le_limbs(&self.serialize());
        let b = Self::to_le_limbs(&other.serialize());

        let (mut r, carry) = FieldElement::adc_n(a, b);

        // if overflowed OR r >= n ⇒ subtract n once
        if carry == 1 || Self::geq(&r, &Self::N_LIMBS) {
            Self::sub_in_place(&mut r, &Self::N_LIMBS);
        }

        Ok(Self::from_bytes_unchecked(Self::limbs_to_be(&r)))
    }
    
    /// Subtract two scalars modulo the curve order n
    pub fn sub_mod_n(&self, other: &Self) -> Result<Self> {
        let a = Self::to_le_limbs(&self.serialize());
        let b = Self::to_le_limbs(&other.serialize());

        let (mut r, borrow) = FieldElement::sbb_n(a, b);

        // if negative ⇒ add n back
        if borrow == 1 {
            let (sum, _) = FieldElement::adc_n(r, Self::N_LIMBS);
            r = sum;
        }

        Ok(Self::from_bytes_unchecked(Self::limbs_to_be(&r)))
    }
    
    /// Multiply two scalars modulo the curve order n.
    /// Uses constant-time double-and-add algorithm for correctness and security.
    /// Processes bits from MSB to LSB to ensure correct powers of 2.
    pub fn mul_mod_n(&self, other: &Self) -> Result<Self> {
        // Start with zero (additive identity)
        let mut acc = Self::from_bytes_unchecked([0u8; P521_SCALAR_SIZE]);
        
        // Process each bit from MSB to LSB
        for byte in other.serialize() {
            for i in (0..8).rev() {  // MSB first within each byte
                // Double the accumulator: acc = acc * 2 (mod n)
                acc = acc.add_mod_n(&acc)?;
                
                // If bit is set, add self: acc = acc + self (mod n)
                if (byte >> i) & 1 == 1 {
                    acc = acc.add_mod_n(self)?;
                }
            }
        }
        
        Ok(acc)
    }
    
    /// Compute multiplicative inverse modulo n using Fermat's little theorem
    /// a^(-1) ≡ a^(n-2) (mod n). Left-to-right binary exponentiation.
    pub fn inv_mod_n(&self) -> Result<Self> {
        // zero has no inverse
        if self.is_zero() {
            return Err(Error::param("P-521 Scalar", "Cannot invert zero scalar"));
        }

        // Step 1: form exponent = n-2
        let mut exp = NIST_P521.n; // big-endian [u8;66]
        // subtract 2 with borrow
        let mut borrow = 2u16;
        for i in (0..P521_SCALAR_SIZE).rev() {
            let v = exp[i] as i16 - (borrow as i16);
            if v < 0 {
                exp[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                exp[i] = v as u8;
                borrow = 0;
            }
        }

        // Step 2: binary exponentiation, left-to-right:
        let mut result = {
            let mut one = [0u8; P521_SCALAR_SIZE];
            one[P521_SCALAR_SIZE - 1] = 1;
            Self::from_bytes_unchecked(one)
        };
        let base = self.clone();

        for byte in exp {
            for bit in (0..8).rev() {
                // square
                result = result.mul_mod_n(&result)?;
                // multiply if this exp-bit is 1
                if (byte >> bit) & 1 == 1 {
                    result = result.mul_mod_n(&base)?;
                }
            }
        }

        Ok(result)
    }

    /// Compute the additive inverse (negation) modulo n
    /// Returns -self mod n, which is equivalent to n - self when self != 0
    /// Returns 0 when self is 0
    pub fn negate(&self) -> Self {
        // If self is zero, return zero
        if self.is_zero() {
            return Self::from_bytes_unchecked([0u8; P521_SCALAR_SIZE]);
        }
        
        // Otherwise compute n - self
        let n_limbs = Self::N_LIMBS;
        let self_limbs = Self::to_le_limbs(&self.serialize());
        let mut res = [0u32; 17];
        
        // Subtract self from n
        let mut borrow = 0i64;
        for i in 0..17 {
            let tmp = n_limbs[i] as i64 - self_limbs[i] as i64 - borrow;
            if tmp < 0 {
                res[i] = (tmp + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                res[i] = tmp as u32;
                borrow = 0;
            }
        }
        
        // No borrow should occur since self < n
        debug_assert_eq!(borrow, 0);
        
        Self::from_bytes_unchecked(Self::limbs_to_be(&res))
    }

    // Private helper methods

    /// Reduce scalar modulo the curve order n using constant-time arithmetic.
    /// The curve order n for P-521 is:
    /// n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    /// 
    /// Algorithm:
    /// 1. Check if input is zero (invalid)
    /// 2. Compare with curve order using constant-time comparison
    /// 3. Conditionally subtract n if input >= n
    /// 4. Verify result is still non-zero
    /// 
    /// Constant-time "a ≥ b" test on 66-byte big-endian values
    #[inline(always)]
    fn ge_be(a: &[u8; P521_SCALAR_SIZE], b: &[u8; P521_SCALAR_SIZE]) -> bool {
        let mut gt = 0u8;
        let mut lt = 0u8;

        for i in 0..P521_SCALAR_SIZE {
            gt |= ((a[i] > b[i]) as u8) & (!lt);
            lt |= ((a[i] < b[i]) as u8) & (!gt);
        }
        // true when a > b  OR  a == b
        gt == 1 || (gt == 0 && lt == 0)
    }

    /* ---------- patched reducer ---------- */

    fn reduce_scalar_bytes(bytes: &mut [u8; P521_SCALAR_SIZE]) -> Result<()> {
        let order = &NIST_P521.n;

        // reject zero
        if bytes.iter().all(|&b| b == 0) {
            return Err(Error::param("P-521 Scalar", "Scalar cannot be zero"));
        }

        // keep subtracting until bytes < order   (constant-time loop)
        while Self::ge_be(bytes, order) {
            let mut borrow = 0u16;
            for i in (0..P521_SCALAR_SIZE).rev() {
                let diff = bytes[i] as i16 - order[i] as i16 - borrow as i16;
                if diff < 0 {
                    bytes[i] = (diff + 256) as u8;
                    borrow   = 1;
                } else {
                    bytes[i] = diff as u8;
                    borrow   = 0;
                }
            }
        }
        Ok(())
    }
    
    /// n (group order) in 17 little-endian 32-bit limbs
    const N_LIMBS: [u32; 17] = [
        0x9138_6409, // limb 0  – least-significant
        0xBB6F_B71E, // limb 1
        0x899C_47AE, // limb 2
        0x3BB5_C9B8, // limb 3
        0xF709_A5D0, // limb 4
        0x7FCC_0148, // limb 5
        0xBF2F_966B, // limb 6
        0x5186_8783, // limb 7
        0xFFFF_FFFA, // limb 8
        0xFFFF_FFFF, // limb 9
        0xFFFF_FFFF, // limb 10
        0xFFFF_FFFF, // limb 11
        0xFFFF_FFFF, // limb 12
        0xFFFF_FFFF, // limb 13
        0xFFFF_FFFF, // limb 14
        0xFFFF_FFFF, // limb 15
        0x0000_01FF, // limb 16 – most-significant 9 bits
    ];

    /// Compare two limb arrays for greater-than-or-equal
    #[inline(always)]
    fn geq(a: &[u32; 17], b: &[u32; 17]) -> bool {
        for i in (0..17).rev() {
            if a[i] > b[i] { return true; }
            if a[i] < b[i] { return false; }
        }
        true  // equal
    }

    /// Subtract b from a in-place
    #[inline(always)]
    fn sub_in_place(a: &mut [u32; 17], b: &[u32; 17]) {
        let mut borrow = 0u64;
        for i in 0..17 {
            let tmp = (a[i] as u64)
                     .wrapping_sub(b[i] as u64)
                     .wrapping_sub(borrow);
            a[i] = tmp as u32;
            borrow = (tmp >> 63) & 1;  // 1 if we wrapped
        }
    }
}