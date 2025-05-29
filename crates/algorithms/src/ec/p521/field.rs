//! P-521 field arithmetic implementation (Fₚ for p = 2^521 − 1)
//!
//! This file implements the heavy-weight primitives for P-521 field arithmetic:
//! full-width multiplication, squaring, modular inversion and modular square-root.
//! The design philosophy matches our existing P-256 / P-384 field modules:
//!   * pure Rust, constant-time where it matters.
//!   * 32-bit little-endian limbs stored in `[u32; 17]` (544 bits, only the
//!     lower 521 are used).
//!   * reduction uses the Mersenne trick for p = 2^521 − 1:
//!          (H · 2^521 + L)  ≡  H + L   (mod p)

use crate::error::{Error, Result};
use crate::ec::p521::constants::{
    P521_FIELD_ELEMENT_SIZE, P521_LIMBS, p521_bytes_to_limbs, p521_limbs_to_bytes
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// P-521 field element representing values in Fₚ (p = 2^521 − 1).
/// Internally stored as 17 little-endian 32-bit limbs; only the low 9 bits
/// of limb 16 are significant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u32; P521_LIMBS]);

impl Zeroize for FieldElement {
    fn zeroize(&mut self) { 
        self.0.zeroize(); 
    }
}

/* ========================================================================== */
/*  Constants                                                                 */
/* ========================================================================== */

impl FieldElement {
    /// p = 2^521 − 1  (little-endian limbs).
    pub(crate) const MOD_LIMBS: [u32; P521_LIMBS] = [
        0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        0x0000_01FF, // limb 16 (only 9 bits used)
    ];

    /// a = −3 mod p  = 2^521 − 4  (little-endian limbs)
    pub(crate) const A_M3: [u32; P521_LIMBS] = [
        0xFFFF_FFFC, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
        0x0000_01FF,
    ];

    /// The additive identity element: 0
    #[inline] 
    pub fn zero() -> Self { 
        FieldElement([0u32; P521_LIMBS]) 
    }
    
    /// The multiplicative identity element: 1
    #[inline] 
    pub fn one() -> Self {
        let mut limbs = [0u32; P521_LIMBS];
        limbs[0] = 1; 
        Self(limbs)
    }
}

/* ========================================================================== */
/*  (De)Serialisation                                                         */
/* ========================================================================== */

impl FieldElement {
    /// Create a field element from big-endian byte representation.
    /// 
    /// Validates that the input represents a value less than the field modulus p.
    /// Returns an error if the value is >= p.
    pub fn from_bytes(bytes: &[u8; P521_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let limbs = p521_bytes_to_limbs(bytes);
        let fe    = FieldElement(limbs);
        if !fe.is_valid() {
            return Err(Error::param("FieldElement P-521", "Value >= modulus"));
        }
        Ok(fe)
    }

    /// Convert field element to big-endian byte representation
    pub fn to_bytes(&self) -> [u8; P521_FIELD_ELEMENT_SIZE] {
        p521_limbs_to_bytes(&self.0)
    }

    /// Check if the field element represents zero
    #[inline(always)]
    pub fn is_zero(&self) -> bool { 
        self.0.iter().all(|&w| w == 0) 
    }
    
    /// Return `true` if the field element is odd (least-significant bit set)
    #[inline(always)]
    pub fn is_odd(&self) -> bool { 
        (self.0[0] & 1) == 1 
    }

    /// self < p ?   (constant-time)
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        let (_, borrow) = Self::sbb_n(self.0, Self::MOD_LIMBS);
        borrow == 1  // borrow = 1  ⇒  self < p
    }
}

/* ========================================================================== */
/*  Core helpers: limb add / sub                                              */
/* ========================================================================== */

impl FieldElement {
    /// N-limb addition with carry.
    #[inline(always)]
    pub(crate) fn adc_n<const N: usize>(a: [u32; N], b: [u32; N]) -> ([u32; N], u32) {
        let mut out   = [0u32; N];
        let mut carry = 0u64;
        for i in 0..N {
            let t = a[i] as u64 + b[i] as u64 + carry;
            out[i] = t as u32;
            carry  = t >> 32;
        }
        (out, carry as u32)
    }

    /// N-limb subtraction with borrow.
    #[inline(always)]
    pub(crate) fn sbb_n<const N: usize>(a: [u32; N], b: [u32; N]) -> ([u32; N], u32) {
        let mut out    = [0u32; N];
        let mut borrow = 0i64;
        for i in 0..N {
            let t = a[i] as i64 - b[i] as i64 - borrow;
            out[i] = t as u32;
            borrow = (t >> 63) & 1;   // 1 if negative
        }
        (out, borrow as u32)
    }

    /// Conditionally select (`flag` = 0 ⇒ *a*, `flag` = 1 ⇒ *b*).
    #[inline(always)]
    fn conditional_select(a: &[u32; P521_LIMBS], b: &[u32; P521_LIMBS], flag: Choice) -> Self {
        let mut out = [0u32; P521_LIMBS];
        for i in 0..P521_LIMBS {
            out[i] = u32::conditional_select(&a[i], &b[i], flag);
        }
        FieldElement(out)
    }

    /// Constant-time conditional swap
    /// 
    /// Swaps the two field elements if choice is 1, leaves them unchanged if choice is 0.
    /// This operation is performed in constant time to prevent timing attacks.
    #[inline(always)]
    pub fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        for i in 0..P521_LIMBS {
            let tmp = u32::conditional_select(&a.0[i], &b.0[i], choice);
            b.0[i] = u32::conditional_select(&b.0[i], &a.0[i], choice);
            a.0[i] = tmp;
        }
    }
}

/* ========================================================================== */
/*  P-521 reduction helper                                                    */
/* ========================================================================== */

impl FieldElement {
    /// Reduce a 34-limb value (little-endian u32) modulo
    /// p = 2²⁵²¹ − 1.  Runs in constant time.
    fn reduce_wide(t: [u32; 34]) -> Self {
        // --------------------------------------------------------------------- //
        // 1.  Split the input in two halves:  L = t[ 0..17],  H = t[17..34]     //
        //     and add       L  +  (H << 23).                                    //
        //     While doing so we fold the overflow of each limb straight away,   //
        //     so we never need more than an 18-limb scratch buffer.             //
        // --------------------------------------------------------------------- //
        let mut acc  = [0u64; 18];        // 17 limbs  + a possible final carry
        let mut c: u64 = 0;

        for i in 0..17 {
            let l = t[i]        as u64;
            let h = t[17 + i]   as u64;

            // low   32 bits of (h << 23)
            let lo = (h << 23) & 0xFFFF_FFFF;
            // overflow  (high bits of the same shift)
            let hi =  h >>  9;            // (32 − 23) = 9

            let tmp   = l + lo + c;
            acc[i]    = tmp & 0xFFFF_FFFF;
            c         = (tmp >> 32) + hi; // propagate both the normal carry
        }
        acc[17] = c;                      // (can be up to 2³³ − 2)

        // --------------------------------------------------------------------- //
        // 2.  Fold the 18-th limb (bit-position 544) once more:                  //
        //         2²⁵⁴⁴  ≡  2²³   (mod p)                                        //
        // --------------------------------------------------------------------- //
        let top = acc[17];
        if top != 0 {
            // add (top << 23) to limb-0   … overflow will bubble to the right
            let tmp   = acc[0] + ((top << 23) & 0xFFFF_FFFF);
            acc[0]    = tmp & 0xFFFF_FFFF;
            let mut c = (tmp >> 32) + (top >> 9);    // carry to propagate

            // propagate through all 17 limbs, *wrapping* when we fall off the end
            for i in 1..=17 {
                let idx  = i % 17;
                let tmp  = acc[idx] + c;
                acc[idx] = tmp & 0xFFFF_FFFF;
                c        =  tmp >> 32;
                if c == 0 { break }
            }
            acc[17] = 0;  // completely folded away
        }

        // --------------------------------------------------------------------- //
        // 3.  Limb-16 must only keep its lowest 9 bits.  Everything above that   //
        //     again represents   k · 2²⁵²¹  and is folded back into limb-0.     //
        // --------------------------------------------------------------------- //
        let extra = acc[16] >> 9;         // at most 23 bits
        acc[16]  &= 0x1FF;
        if extra != 0 {
            let mut i  = 0;
            let mut c  = extra;
            loop {
                let tmp  = acc[i] + c;
                acc[i]   = tmp & 0xFFFF_FFFF;
                c        = tmp >> 32;
                if c == 0 { break }
                i = (i + 1) % 17;
            }
        }

        // --------------------------------------------------------------------- //
        // 4.  Conditional subtraction of the modulus.                           //
        // --------------------------------------------------------------------- //
        let mut limbs = [0u32; 17];
        for i in 0..17 { limbs[i] = acc[i] as u32; }

        let (sub, borrow) = Self::sbb_n(limbs, Self::MOD_LIMBS);
        Self::conditional_select(&limbs, &sub, Choice::from((borrow ^ 1) as u8))
    }

}

/* ========================================================================== */
/*  Public API: add / sub / mul / square / invert / sqrt                      */
/* ========================================================================== */

impl FieldElement {
    /// Constant-time addition modulo p
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = Self::adc_n(self.0, other.0);
        // If there was a carry OR the sum ≥ p  ⇒ subtract once.
        let (sub, borrow) = Self::sbb_n(sum, Self::MOD_LIMBS);
        let need_sub      = Choice::from(((carry | (borrow ^ 1)) & 1) as u8);
        Self::conditional_select(&sum, &sub, need_sub)
    }

    /// Constant-time subtraction modulo p
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = Self::sbb_n(self.0, other.0);
        // If we borrowed ⇒ add p back.
        let (sum, _)       = Self::adc_n(diff, Self::MOD_LIMBS);
        Self::conditional_select(&diff, &sum, Choice::from(borrow as u8))
    }

    /// Field multiplication using school-book multiply + Mersenne reduction.
    pub fn mul(&self, other: &Self) -> Self {
        // ── 1. 17×17 → 34 partial products (128-bit accumulator) ----------
        let mut wide = [0u128; 34];
        for i in 0..17 {
            for j in 0..17 {
                wide[i + j] += (self.0[i] as u128) * (other.0[j] as u128);
            }
        }

        // ── 2. Carry-propagate 128-bit → 34 × 32-bit limbs -----------------
        let mut limbs = [0u32; 34];
        let mut carry: u128 = 0;
        for i in 0..34 {
            let v   = wide[i] + carry;
            limbs[i] = (v & 0xFFFF_FFFF) as u32;
            carry    = v >> 32;
        }
        // `carry` may be non-zero (at most 2^32−1) – push it as limb 34 if so
        if carry != 0 {
            // This is equivalent to a limb 34 that will be folded anyway.
            let extra = carry as u32;
            let (new, of) = limbs[0].overflowing_add(extra);
            limbs[0] = new;
            if of {
                // propagate one more carry (rare)
                let mut k = 1;
                while k < 17 {
                    let (n, o) = limbs[k].overflowing_add(1);
                    limbs[k] = n;
                    if !o { break; }
                    k += 1;
                }
            }
        }

        // ── 3. Reduce back to 17 limbs -------------------------------------
        Self::reduce_wide(limbs)
    }

    /// Field squaring – just a specialised multiplication.
    #[inline(always)]
    pub fn square(&self) -> Self { 
        self.mul(self) 
    }

    /// Fermat-inversion  a^(p−2)  via left-to-right square-and-multiply.
    pub fn invert(&self) -> Result<Self> {
        if self.is_zero() { 
            return Err(Error::param("FieldElement P-521", "Inverse of zero")); 
        }

        // Prepare exponent  p−2  =  (2^521 − 1) − 2  =  2^521 − 3
        //   p  in bytes is   0x01 | 0xFF * 65
        let mut exp = [0u8; P521_FIELD_ELEMENT_SIZE];
        exp[0] = 0x01; 
        for i in 1..66 { 
            exp[i] = 0xFF; 
        }
        // subtract 2                                      (big-endian)
        let mut borrow = 2u16;
        for i in (0..66).rev() {
            let v      = exp[i] as i16 - borrow as i16;
            exp[i]     = if v < 0 { (v + 256) as u8 } else { v as u8 };
            borrow     = if v < 0 { 1 } else { 0 };
        }

        // Left-to-right binary exponentiation
        let mut result = FieldElement::one();
        let mut base   = self.clone();
        for byte in exp.iter() {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 { 
                    result = result.mul(&base); 
                }
            }
        }
        Ok(result)
    }

    /// Square-root via  a^{(p+1)/4}  (because p ≡ 3 mod 4).
    /// (p+1)/4 = 2^519.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() { 
            return Some(Self::zero()); 
        }
        // a^{2^519}
        let mut res = self.clone();
        for _ in 0..519 { 
            res = res.square(); 
        }
        // verify
        if res.square() == *self { 
            Some(res) 
        } else { 
            None 
        }
    }
    
    /// Get the field modulus p as a FieldElement
    pub(crate) fn get_modulus() -> Self {
        FieldElement(Self::MOD_LIMBS)
    }
}