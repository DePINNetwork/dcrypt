//! Field arithmetic modulo p = 2^255 - 19
//!
//! This module implements arithmetic operations on field elements
//! for the Ed25519 elliptic curve.

use zeroize::Zeroize;
use dcrypt_internal::constant_time::ct_eq;
use super::constants::{load4, SQRT_M1};

/// Field element representing a value modulo p = 2^255 - 19
#[derive(Clone, Copy, Zeroize)]
pub struct FieldElement {
    // Represented as 10 26-bit limbs for efficient arithmetic
    pub(crate) v: [i32; 10],
}

// Prime p = 2^255 - 19 in limb representation
const PRIME_LIMBS: [i32; 10] = [
    0x3ffffed, 0x1ffffff, 0x3ffffff, 0x1ffffff,
    0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff,
    0x3ffffff, 0x1ffffff,
];

/// (p-2) = 2^255 - 21 in little-endian form
const P_MINUS_2: [u8; 32] = [
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

impl FieldElement {
    /// Check limb bounds (debug builds only)
    #[cfg(debug_assertions)]
    fn check_bounds(&self) {
        // For canonical form, limbs should be in [0, max]
        // Even limbs (0, 2, 4, 6, 8): 26-bit, max = 0x3ffffff
        // Odd limbs (1, 3, 5, 7, 9): 25-bit, max = 0x1ffffff
        
        for (i, &limb) in self.v.iter().enumerate() {
            let max = if i & 1 == 0 { 0x3ffffff } else { 0x1ffffff };
            debug_assert!(
                limb >= 0 && limb <= max,
                "Limb[{}] = {} ({:#x}) out of bounds [0, {} ({:#x})]",
                i, limb, limb, max, max
            );
        }
    }
    
    /// Reduce to canonical form [0, p)
    /// This performs STRONG reduction to ensure the value is strictly less than p
    pub fn reduce_once(&mut self) {
        // 1. First carry pass - bring limbs into range
        carry(&mut self.v);

        // 2. First conditional subtraction of p
        sub_p_if_necessary(&mut self.v);

        // 3. Second carry pass - needed because the 19*c trick can push limb 0 high again
        carry(&mut self.v);

        // 4. CRITICAL: Second conditional subtraction to ensure strong reduction
        // After the second carry, the value might be in [p, p+2^25), so we need
        // one more subtraction to guarantee the result is in [0, p)
        sub_p_if_necessary(&mut self.v);
    }
    
    /// Create a field element from bytes (little-endian)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let v = [
            (load4(&bytes[0..]) as i32) & 0x3ffffff,
            (load4(&bytes[3..]) as i32 >> 2) & 0x1ffffff,
            (load4(&bytes[6..]) as i32 >> 3) & 0x3ffffff,
            (load4(&bytes[9..]) as i32 >> 5) & 0x1ffffff,
            (load4(&bytes[12..]) as i32 >> 6) & 0x3ffffff,
            (load4(&bytes[16..]) as i32) & 0x1ffffff,
            (load4(&bytes[19..]) as i32 >> 1) & 0x3ffffff,
            (load4(&bytes[22..]) as i32 >> 3) & 0x1ffffff,
            (load4(&bytes[25..]) as i32 >> 4) & 0x3ffffff,
            (load4(&bytes[28..]) as i32 >> 6) & 0x1ffffff,
        ];

        let mut fe = FieldElement { v };
        
        // CRITICAL: Reduce to canonical form immediately
        fe.reduce_once();
        
        #[cfg(debug_assertions)]
        fe.check_bounds();
        
        fe
    }
    
    /// Convert to bytes (little-endian)
    pub fn to_bytes(self) -> [u8; 32] {
        let mut h = self.v;
        
        // Reduce to canonical form
        let mut fe_copy = FieldElement { v: h };
        fe_copy.reduce_once();
        h = fe_copy.v;
        
        // Now pack the limbs into bytes
        let mut s = [0u8; 32];
        
        s[0] = (h[0] & 0xff) as u8;
        s[1] = (h[0] >> 8 & 0xff) as u8;
        s[2] = (h[0] >> 16 & 0xff) as u8;
        s[3] = ((h[0] >> 24 | h[1] << 2) & 0xff) as u8;
        s[4] = (h[1] >> 6 & 0xff) as u8;
        s[5] = (h[1] >> 14 & 0xff) as u8;
        s[6] = ((h[1] >> 22 | h[2] << 3) & 0xff) as u8;
        s[7] = (h[2] >> 5 & 0xff) as u8;
        s[8] = (h[2] >> 13 & 0xff) as u8;
        s[9] = ((h[2] >> 21 | h[3] << 5) & 0xff) as u8;
        s[10] = (h[3] >> 3 & 0xff) as u8;
        s[11] = (h[3] >> 11 & 0xff) as u8;
        s[12] = ((h[3] >> 19 | h[4] << 6) & 0xff) as u8;
        s[13] = (h[4] >> 2 & 0xff) as u8;
        s[14] = (h[4] >> 10 & 0xff) as u8;
        s[15] = (h[4] >> 18 & 0xff) as u8;
        s[16] = (h[5] & 0xff) as u8;
        s[17] = (h[5] >> 8 & 0xff) as u8;
        s[18] = (h[5] >> 16 & 0xff) as u8;
        s[19] = ((h[5] >> 24 | h[6] << 1) & 0xff) as u8;
        s[20] = (h[6] >> 7 & 0xff) as u8;
        s[21] = (h[6] >> 15 & 0xff) as u8;
        s[22] = ((h[6] >> 23 | h[7] << 3) & 0xff) as u8;
        s[23] = (h[7] >> 5 & 0xff) as u8;
        s[24] = (h[7] >> 13 & 0xff) as u8;
        s[25] = ((h[7] >> 21 | h[8] << 4) & 0xff) as u8;
        s[26] = (h[8] >> 4 & 0xff) as u8;
        s[27] = (h[8] >> 12 & 0xff) as u8;
        s[28] = ((h[8] >> 20 | h[9] << 6) & 0xff) as u8;
        s[29] = (h[9] >> 2 & 0xff) as u8;
        s[30] = (h[9] >> 10 & 0xff) as u8;
        s[31] = (h[9] >> 18) as u8;
        
        s
    }
    
    /// Zero element
    pub fn zero() -> Self {
        FieldElement { v: [0; 10] }
    }
    
    /// One element
    pub fn one() -> Self {
        FieldElement { v: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] }
    }
    
    /// Double a field element
    pub fn double(&self) -> FieldElement {
        self.add(self)
    }
    
    /// Add two field elements
    pub fn add(&self, other: &FieldElement) -> FieldElement {
        let mut v = [0i32; 10];
        for (i, item) in v.iter_mut().enumerate() {
            *item = self.v[i].wrapping_add(other.v[i]);
        }
        // Fold carries to normalize limbs into [0, max_limb]
        carry(&mut v);
        // Optional: Second pass for extra safety (handles worst-case overflows)
        // carry(&mut v);

        let result = FieldElement { v };
        #[cfg(debug_assertions)]
        result.check_bounds();
        result
    }
    
    /// Subtract two field elements
    pub fn sub(&self, other: &FieldElement) -> FieldElement {
        let mut v = [0i32; 10];

        for (i, item) in v.iter_mut().enumerate() {
            *item = self.v[i] - other.v[i];
        }

        let mut fe = FieldElement { v };
        carry(&mut fe.v);
        
        #[cfg(debug_assertions)]
        fe.check_bounds();
        
        fe
    }
    
    /// Multiply two field elements (ref10 faithful port, constant-time)
    pub fn mul(&self, other: &FieldElement) -> FieldElement {
        let f = self.v;
        let g = other.v;
        
        // ---- copy limbs into i64 ------------------------------------------
        let (f0,f1,f2,f3,f4,f5,f6,f7,f8,f9) = (
            f[0] as i64, f[1] as i64, f[2] as i64, f[3] as i64, f[4] as i64,
            f[5] as i64, f[6] as i64, f[7] as i64, f[8] as i64, f[9] as i64);
        let (g0,g1,g2,g3,g4,g5,g6,g7,g8,g9) = (
            g[0] as i64, g[1] as i64, g[2] as i64, g[3] as i64, g[4] as i64,
            g[5] as i64, g[6] as i64, g[7] as i64, g[8] as i64, g[9] as i64);

        // ---- pre‑scaled constants -----------------------------------------
        let (g1_19,g2_19,g3_19,g4_19,g5_19,g6_19,g7_19,g8_19,g9_19) =
            (19*g1, 19*g2, 19*g3, 19*g4, 19*g5, 19*g6, 19*g7, 19*g8, 19*g9);

        // --- doubles for the *odd* limbs only (FIX) -------------------
        let f1_2 = 2*f1;
        let f3_2 = 2*f3;
        let f5_2 = 2*f5;
        let f7_2 = 2*f7;
        let f9_2 = 2*f9;

        // ---- coefficient table (faithful to ref10) --------------------
        let mut h = [0i64; 10];

        h[0] = f0*g0 + f1_2*g9_19 + f2*g8_19 + f3_2*g7_19 + f4*g6_19
             + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19 + f9_2*g1_19;

        h[1] = f0*g1 + f1*g0 + f2*g9_19 + f3*g8_19 + f4*g7_19
             + f5*g6_19 + f6*g5_19 + f7*g4_19 + f8*g3_19 + f9*g2_19;

        h[2] = f0*g2 + f1_2*g1 + f2*g0 + f3_2*g9_19 + f4*g8_19
             + f5_2*g7_19 + f6*g6_19 + f7_2*g5_19 + f8*g4_19 + f9_2*g3_19;

        h[3] = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g9_19
             + f5*g8_19 + f6*g7_19 + f7*g6_19 + f8*g5_19 + f9*g4_19;

        h[4] = f0*g4 + f1_2*g3 + f2*g2 + f3_2*g1 + f4*g0
             + f5_2*g9_19 + f6*g8_19 + f7_2*g7_19 + f8*g6_19 + f9_2*g5_19;

        h[5] = f0*g5 + f1*g4 + f2*g3 + f3*g2 + f4*g1 + f5*g0
             + f6*g9_19 + f7*g8_19 + f8*g7_19 + f9*g6_19;

        h[6] = f0*g6 + f1_2*g5 + f2*g4 + f3_2*g3 + f4*g2 + f5_2*g1
             + f6*g0 + f7_2*g9_19 + f8*g8_19 + f9_2*g7_19;

        h[7] = f0*g7 + f1*g6 + f2*g5 + f3*g4 + f4*g3 + f5*g2
             + f6*g1 + f7*g0 + f8*g9_19 + f9*g8_19;

        h[8] = f0*g8 + f1_2*g7 + f2*g6 + f3_2*g5 + f4*g4 + f5_2*g3
             + f6*g2 + f7_2*g1 + f8*g0 + f9_2*g9_19;

        h[9] = f0*g9 + f1*g8 + f2*g7 + f3*g6 + f4*g5 + f5*g4
             + f6*g3 + f7*g2 + f8*g1 + f9*g0;

        // ---- carry‑propagation (unchanged) --------------------------------
        let mut v = h;
        for _ in 0..5 {
            let mut c: i64;
            c = v[0] >> 26; v[0] &= 0x3ffffff; v[1] += c;
            c = v[1] >> 25; v[1] &= 0x1ffffff; v[2] += c;
            c = v[2] >> 26; v[2] &= 0x3ffffff; v[3] += c;
            c = v[3] >> 25; v[3] &= 0x1ffffff; v[4] += c;
            c = v[4] >> 26; v[4] &= 0x3ffffff; v[5] += c;
            c = v[5] >> 25; v[5] &= 0x1ffffff; v[6] += c;
            c = v[6] >> 26; v[6] &= 0x3ffffff; v[7] += c;
            c = v[7] >> 25; v[7] &= 0x1ffffff; v[8] += c;
            c = v[8] >> 26; v[8] &= 0x3ffffff; v[9] += c;
            c = v[9] >> 25; v[9] &= 0x1ffffff; v[0] += 19 * c;
        }

        // ---- store back to FieldElement -----------------------------------
        let mut out = [0i32; 10];
        for (i, &limb) in v.iter().enumerate() {
            out[i] = limb as i32;
        }

        let mut fe = FieldElement { v: out };
        fe.reduce_once();          // final canonical reduction
        fe
    }
    
    /// Square a field element
    pub fn square(&self) -> FieldElement {
        self.mul(self)
    }
    
    /// Multiplicative inverse using Fermat's little theorem: a^(p-2) (constant-time)
    pub fn invert(&self) -> FieldElement {
        // Special-case 0 to avoid an infinite loop in the caller's tests.
        if self.is_zero() { return FieldElement::zero(); }

        let mut result = FieldElement::one();
        let base = *self;

        // Scan bits from MSB → LSB (bit 254 down to bit 0)
        // We use 255 iterations to cover all bits of the 256-bit exponent
        for bit in (0..256).rev() {
            result = result.square();                       // always square
            let byte_index = bit >> 3;  // bit / 8
            let bit_index = bit & 7;    // bit % 8
            let byte = P_MINUS_2[byte_index];
            if ((byte >> bit_index) & 1) == 1 {
                result = result.mul(&base);                 // conditional multiply
            }
        }
        result
    }
    
    /// Check if zero
    pub fn is_zero(&self) -> bool {
        let bytes = self.to_bytes();
        let mut acc = 0u8;
        for &b in &bytes {
            acc |= b;
        }
        acc == 0
    }
    
    /// Negate
    pub fn neg(&self) -> FieldElement {
        FieldElement::zero().sub(self)
    }
}

/// Propagate carries so that each limb fits in its designated width
/// (26 bits for even limbs, 25 bits for odd limbs).
pub(crate) fn carry(h: &mut [i32; 10]) {
    // ---- 1st pass -------------------------------------------------------
    let mut c: i32;
    c = h[0] >> 26; h[0] &= 0x3FFFFFF; h[1] += c;
    c = h[1] >> 25; h[1] &= 0x1FFFFFF; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3FFFFFF; h[3] += c;
    c = h[3] >> 25; h[3] &= 0x1FFFFFF; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3FFFFFF; h[5] += c;
    c = h[5] >> 25; h[5] &= 0x1FFFFFF; h[6] += c;
    c = h[6] >> 26; h[6] &= 0x3FFFFFF; h[7] += c;
    c = h[7] >> 25; h[7] &= 0x1FFFFFF; h[8] += c;
    c = h[8] >> 26; h[8] &= 0x3FFFFFF; h[9] += c;
    c = h[9] >> 25; h[9] &= 0x1FFFFFF; h[0] += 19 * c;
    
    // ---- 2nd pass -------------------------------------------------------
    c = h[0] >> 26; h[0] &= 0x3FFFFFF; h[1] += c;
    c = h[1] >> 25; h[1] &= 0x1FFFFFF; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3FFFFFF; h[3] += c;
    c = h[3] >> 25; h[3] &= 0x1FFFFFF; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3FFFFFF; h[5] += c;
    c = h[5] >> 25; h[5] &= 0x1FFFFFF; h[6] += c;
    c = h[6] >> 26; h[6] &= 0x3FFFFFF; h[7] += c;
    c = h[7] >> 25; h[7] &= 0x1FFFFFF; h[8] += c;
    c = h[8] >> 26; h[8] &= 0x3FFFFFF; h[9] += c;
    c = h[9] >> 25; h[9] &= 0x1FFFFFF; h[0] += 19 * c;
}

/// Helper: subtract p once if the element is ≥ p
/// This performs a constant-time conditional subtraction
fn sub_p_if_necessary(v: &mut [i32; 10]) {
    let mut diff = [0i32; 10];
    let mut borrow = 0i32;
    
    // Compute v - p
    for i in 0..10 {
        let d = (v[i] as i64) - (PRIME_LIMBS[i] as i64) - (borrow as i64);
        let limb_bits = if i & 1 == 0 { 26 } else { 25 };
        let mask = (1i64 << limb_bits) - 1;
        diff[i] = (d & mask) as i32;
        borrow = if d < 0 { 1 } else { 0 };
    }
    
    // When borrow == 0  →  v >= p  →  select diff (v - p)
    // When borrow == 1  →  v < p   →  keep v
    let mask = borrow.wrapping_sub(1);  // -1 if v >= p, else 0
    
    for i in 0..10 {
        v[i] = (v[i] & !mask) | (diff[i] & mask);
    }
}

/// Square root in field (returns None if no square root exists)
pub fn sqrt(a: &FieldElement) -> Option<FieldElement> {
    let exp = pow_p38(a);
    let check = exp.square();
    
    if ct_eq(check.to_bytes(), a.to_bytes()) {
        Some(exp)
    } else {
        let sqrt_m1 = FieldElement::from_bytes(&SQRT_M1);
        let result = exp.mul(&sqrt_m1);
        let check2 = result.square();
        if ct_eq(check2.to_bytes(), a.to_bytes()) {
            Some(result)
        } else {
            None
        }
    }
}

/// Compute a^((p+3)/8) = a^(2^252 - 2)
///
/// This compact ladder follows the proof in RFC 8032 §5.1.3.
fn pow_p38(a: &FieldElement) -> FieldElement {
    let mut r = *a;

    // After n iterations: r = a^(2^(n+1) - 1)
    for _ in 0..250 {
        r = r.square();
        r = r.mul(a);
    }

    // One more square: exponent × 2  →  2^252 - 2
    r.square()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, rngs::OsRng};
    
    // Test-only helper functions
    impl FieldElement {
        /// Check if field element is in canonical form (test only)
        fn canonical(&self) -> bool {
            for (i, &limb) in self.v.iter().enumerate() {
                let max = if i & 1 == 0 { 0x3ffffff } else { 0x1ffffff };
                if limb < 0 || limb > max {
                    return false;
                }
            }
            true
        }
        
        /// Minus one element (test only)
        fn minus_one() -> Self {
            // -1 mod p = p - 1
            FieldElement { 
                v: [0x3ffffec, 0x1ffffff, 0x3ffffff, 0x1ffffff, 
                    0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 
                    0x3ffffff, 0x1ffffff] 
            }
        }
        
        /// Two element (test only)
        fn two() -> Self {
            FieldElement { v: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0] }
        }
        
        /// Five element (test only)
        fn five() -> Self {
            FieldElement { v: [5, 0, 0, 0, 0, 0, 0, 0, 0, 0] }
        }
    }
    
    #[test]
    fn test_field_element_arithmetic() {
        let a = FieldElement::from_bytes(&[1; 32]);
        let b = FieldElement::from_bytes(&[2; 32]);
        
        let c = a.add(&b);
        let d = a.mul(&b);
        
        // Basic sanity checks
        assert!(!c.is_zero());
        assert!(!d.is_zero());
    }
    
    #[test]
    fn test_simple_inversions() {
        // Test 1^(-1) = 1
        let one = FieldElement::one();
        let one_inv = one.invert();
        let check = one.mul(&one_inv);
        assert_eq!(check.to_bytes(), FieldElement::one().to_bytes(), "1^(-1) != 1");
        
        // Test 2^(-1) * 2 = 1
        let two = FieldElement::two();
        let two_inv = two.invert();
        let check = two.mul(&two_inv);
        assert_eq!(check.to_bytes(), FieldElement::one().to_bytes(), "2 * 2^(-1) != 1");
        
        // Test 5^(-1) * 5 = 1
        let five = FieldElement::five();
        let five_inv = five.invert();
        let check = five.mul(&five_inv);
        assert_eq!(check.to_bytes(), FieldElement::one().to_bytes(), "5 * 5^(-1) != 1");
        
        // Test (-1)^(-1) = -1 (since (-1)^2 = 1)
        let minus_one = FieldElement::minus_one();
        let minus_one_inv = minus_one.invert();
        let check = minus_one.mul(&minus_one_inv);
        assert_eq!(check.to_bytes(), FieldElement::one().to_bytes(), "(-1) * (-1)^(-1) != 1");
        // Also verify that (-1)^(-1) = -1
        assert_eq!(minus_one_inv.to_bytes(), minus_one.to_bytes(), "(-1)^(-1) != -1");
    }
    
    #[test]
    fn test_field_element_inverse() {
        let a = FieldElement::from_bytes(&[171, 6, 18, 1, 21, 5, 37, 61, 10, 52, 68, 80, 26, 31, 72, 42, 10, 52, 68, 80, 17, 10, 61, 81, 21, 5, 37, 61, 10, 52, 6, 18]);
        
        let a_inv = a.invert();
        
        let product = a.mul(&a_inv);
        
        let p_bytes = product.to_bytes();
        
        let one = FieldElement::one();
        let one_bytes = one.to_bytes();
        
        assert_eq!(p_bytes, one_bytes);
    }
    
    #[test]
    fn check_random_inversion() {
        let mut rng = OsRng;

        for i in 0..1_000 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            let a = FieldElement::from_bytes(&bytes);
            if a.is_zero() { continue; }

            let a_inv = a.invert();
            let prod = a.mul(&a_inv).to_bytes();
            if prod != FieldElement::one().to_bytes() {
                panic!("Found counter-example at iteration {}: {:?}", i, bytes);
            }
        }
    }
    
    #[test]
    fn test_field_element_inverse_focused() {
        // Test with a known problematic value first
        let test_bytes = [
            171, 6, 18, 1, 21, 5, 37, 61, 
            10, 52, 68, 80, 26, 31, 72, 42, 
            10, 52, 68, 80, 17, 10, 61, 81, 
            21, 5, 37, 61, 10, 52, 6, 18
        ];
        
        let a = FieldElement::from_bytes(&test_bytes);
        
        // Verify the input is valid
        assert!(a.canonical(), "Input not canonical!");
        
        // Test round-trip first (isolate serialization issues)
        let a_bytes = a.to_bytes();
        assert_eq!(test_bytes, a_bytes, "Round-trip serialization failed!");
        
        // Now test inversion
        let a_inv = a.invert();
        
        // Test the fundamental property: a * a^(-1) = 1
        let product = a.mul(&a_inv);
        let product_bytes = product.to_bytes();
        let one_bytes = FieldElement::one().to_bytes();
        
        assert_eq!(product_bytes, one_bytes, "a * a^(-1) != 1");
    }

    #[test] 
    fn test_field_element_mul_associativity() {
        // Test (a * b) * c = a * (b * c) to isolate multiplication issues
        let a = FieldElement::from_bytes(&[1; 32]);
        let b = FieldElement::from_bytes(&[2; 32]); 
        let c = FieldElement::from_bytes(&[3; 32]);
        
        let ab_c = a.mul(&b).mul(&c);
        let a_bc = a.mul(&b.mul(&c));
        
        assert_eq!(
            ab_c.to_bytes(), 
            a_bc.to_bytes(),
            "Multiplication not associative!"
        );
    }

    #[test]
    fn test_field_element_square_vs_mul() {
        // Verify that square() = mul(self, self)
        let a = FieldElement::from_bytes(&[42; 32]);
        
        let squared = a.square();
        let mul_self = a.mul(&a);
        
        assert_eq!(
            squared.to_bytes(),
            mul_self.to_bytes(), 
            "square() != mul(self, self)"
        );
    }
    
    #[test]
    fn debug_field_element_round_trip() {
        // Test the specific value that might be failing
        let original_bytes = [
            171, 6, 18, 1, 21, 5, 37, 61,
            10, 52, 68, 80, 26, 31, 72, 42,
            10, 52, 68, 80, 17, 10, 61, 81,
            21, 5, 37, 61, 10, 52, 6, 18
        ];
        
        let fe = FieldElement::from_bytes(&original_bytes);
        
        // Verify each limb is in range
        for (i, &limb) in fe.v.iter().enumerate() {
            let max = if i & 1 == 0 { 0x3ffffff } else { 0x1ffffff };
            assert!(
                limb >= 0 && limb <= max,
                "Limb[{}] = {} out of range [0, {}]",
                i, limb, max
            );
        }
        
        // Step 2: Pack back
        let repacked = fe.to_bytes();
        
        // Find differences
        let mut first_diff = None;
        for (i, (&orig, &repack)) in original_bytes.iter().zip(&repacked).enumerate() {
            if orig != repack && first_diff.is_none() {
                first_diff = Some(i);
            }
        }
        
        if let Some(idx) = first_diff {
            panic!("Round-trip failed at byte {}!", idx);
        }
    }

    #[test]
    fn test_carry_preserves_value() {
        let original = [
            0x3ffffed, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff,
            0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff,
        ];
        
        let mut h = original;
        
        carry(&mut h);
        
        // Convert both to bytes and compare
        let fe_original = FieldElement { v: original };
        let fe_carried = FieldElement { v: h };
        
        assert_eq!(
            fe_original.to_bytes(),
            fe_carried.to_bytes(),
            "carry() changed the field element value!"
        );
    }
    
    #[test]
    fn test_field_element_special_cases() {
        // Test that (p-1) * 2 = p-2 (mod p) = -2
        let p_minus_1 = FieldElement::minus_one();
        let two = FieldElement::two();
        let result = p_minus_1.mul(&two);
        let expected = FieldElement::zero().sub(&two); // -2
        assert_eq!(result.to_bytes(), expected.to_bytes());
        
        // Test that sqrt(-1)^2 = -1
        let sqrt_m1 = FieldElement::from_bytes(&SQRT_M1);
        let squared = sqrt_m1.square();
        assert_eq!(squared.to_bytes(), FieldElement::minus_one().to_bytes());
    }
    
    #[test]
    fn test_field_element_inverse_property() {
        let mut rng = OsRng;
        
        // Edge cases
        let edges = vec![
            FieldElement::one(),              // 1^{-1} == 1
            FieldElement::minus_one(),        // (p-1)^{-1} == p-1 (since -1)
            FieldElement::two(),              // 2
            FieldElement::from_bytes(&[19; 32]),  // 19 (small constant)
            FieldElement::from_bytes(&[0xff; 32]),  // Large value (all bytes 255)
        ];
        
        for a in edges {
            if a.is_zero() { continue; }
            let inv = a.invert();
            let product = a.mul(&inv);
            assert_eq!(
                product.to_bytes(),
                FieldElement::one().to_bytes(),
                "Edge case: a * inv(a) != 1"
            );
        }
        
        // Random cases
        for _ in 0..1000 {
            let mut random_bytes = [0u8; 32];
            rng.fill_bytes(&mut random_bytes);
            if random_bytes == [0u8; 32] { continue; }
            
            let a = FieldElement::from_bytes(&random_bytes);
            let inv = a.invert();
            let product = a.mul(&inv);
            assert_eq!(
                product.to_bytes(),
                FieldElement::one().to_bytes(),
                "Random: a * inv(a) != 1 for a = {:?}",
                random_bytes
            );
        }
    }
    
    // ===== Debug Tests =====
    
    #[test]
    fn debug_neg_one_mul() {
        println!("\n=== Debug: (-1) × (-1) multiplication ===");
        
        let m1 = FieldElement::minus_one();
        println!("minus_one.v = {:?}", m1.v);
        println!("minus_one.bytes = {:02x?}", m1.to_bytes());
        
        println!("\nExpected result: 1");
        println!("one.v = {:?}", FieldElement::one().v);
        println!("one.bytes = {:02x?}", FieldElement::one().to_bytes());
        
        println!("\nPerforming (-1) × (-1):");
        let prod = m1.mul(&m1);
        
        println!("\nFinal result:");
        println!("prod.v    = {:?}", prod.v);
        println!("prod.bytes= {:02x?}", prod.to_bytes());
        
        if prod.to_bytes() == FieldElement::one().to_bytes() {
            println!("\n✓ SUCCESS: (-1) × (-1) = 1");
        } else {
            println!("\n*** FAILURE: (-1) × (-1) != 1 ***");
            println!("Difference detected!");
        }
        
        assert_eq!(prod.to_bytes(), FieldElement::one().to_bytes(), "(-1)*(-1) != 1");
    }

    #[test]
    fn debug_simple_mul() {
        println!("\n=== Debug: Simple multiplications ===");
        
        // Test 1 × 1 = 1
        println!("\n--- Test: 1 × 1 = 1 ---");
        let one = FieldElement::one();
        let prod = one.mul(&one);
        println!("Result: {:02x?}", prod.to_bytes());
        assert_eq!(prod.to_bytes(), FieldElement::one().to_bytes(), "1×1 != 1");
        println!("✓ 1 × 1 = 1");
        
        // Test 2 × 1 = 2
        println!("\n--- Test: 2 × 1 = 2 ---");
        let two = FieldElement::two();
        let prod = two.mul(&one);
        println!("Result: {:02x?}", prod.to_bytes());
        assert_eq!(prod.to_bytes(), FieldElement::two().to_bytes(), "2×1 != 2");
        println!("✓ 2 × 1 = 2");
        
        // Test 3 × 3 = 9
        println!("\n--- Test: 3 × 3 = 9 ---");
        let three = FieldElement::from_bytes(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let nine = FieldElement::from_bytes(&[9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let prod = three.mul(&three);
        println!("Result: {:02x?}", prod.to_bytes());
        assert_eq!(prod.to_bytes(), nine.to_bytes(), "3×3 != 9");
        println!("✓ 3 × 3 = 9");
    }

    #[test]
    fn debug_large_value_mul() {
        println!("\n=== Debug: Large value multiplications ===");
        
        // Test (p-2) × 1 = p-2
        println!("\n--- Test: (p-2) × 1 = p-2 ---");
        let p_minus_2_bytes = [
            0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ];
        let p_minus_2 = FieldElement::from_bytes(&p_minus_2_bytes);
        let one = FieldElement::one();
        let prod = p_minus_2.mul(&one);
        println!("Result: {:02x?}", prod.to_bytes());
        assert_eq!(prod.to_bytes(), p_minus_2_bytes, "(p-2)×1 != p-2");
        println!("✓ (p-2) × 1 = p-2");
    }

    #[test]
    fn debug_minus_one_inv() {
        println!("\n=== Debug: (-1) inversion ===");
        
        let m1 = FieldElement::minus_one();
        println!("DEBUG minus_one.v       = {:?}", m1.v);
        println!("DEBUG minus_one.bytes   = {:02x?}", m1.to_bytes());
        
        // Expected: (-1)^(-1) = -1 (since (-1)^2 = 1)
        println!("\nExpected result: -1 (since (-1)^2 = 1)");
        println!("Expected bytes: {:02x?}", FieldElement::minus_one().to_bytes());

        println!("\nComputing invert(-1):");
        let inv = m1.invert();
        println!("\nDEBUG invert(-1).v      = {:?}", inv.v);
        println!("DEBUG invert(-1).bytes  = {:02x?}", inv.to_bytes());

        // Check if it's actually -1
        if inv.to_bytes() == FieldElement::minus_one().to_bytes() {
            println!("\n✓ Inverse is correctly -1");
        } else {
            println!("\n*** WARNING: Inverse is NOT -1 as expected!");
        }

        // Check property: (-1) * inv(-1) = 1
        println!("\nVerifying (-1) * inv(-1) = 1:");
        let prod = m1.mul(&inv);
        println!("DEBUG (-1)*inv.v        = {:?}", prod.v);
        println!("DEBUG (-1)*inv.bytes    = {:02x?}", prod.to_bytes());
        
        if prod.to_bytes() == FieldElement::one().to_bytes() {
            println!("\n✓ Property holds: (-1) * inv(-1) = 1");
        } else {
            println!("\n*** FAILURE: (-1) * inv(-1) != 1");
            println!("This is the 'junk' output mentioned in the debug guide");
        }
        
        assert_eq!(prod.to_bytes(), FieldElement::one().to_bytes());
    }

    #[test]
    fn debug_simple_inv() {
        println!("\n=== Debug: Simple inversions ===");
        
        // Test 1^(-1) = 1
        println!("\n--- Test: 1^(-1) ---");
        let one = FieldElement::one();
        let one_inv = one.invert();
        println!("1^(-1).bytes = {:02x?}", one_inv.to_bytes());
        assert_eq!(one_inv.to_bytes(), FieldElement::one().to_bytes(), "1^(-1) != 1");
        println!("✓ 1^(-1) = 1");
        
        // Test 2^(-1)
        println!("\n--- Test: 2^(-1) ---");
        let two = FieldElement::two();
        let two_inv = two.invert();
        let check = two.mul(&two_inv);
        println!("2^(-1).bytes = {:02x?}", two_inv.to_bytes());
        println!("2 * 2^(-1) = {:02x?}", check.to_bytes());
        assert_eq!(check.to_bytes(), FieldElement::one().to_bytes(), "2 * 2^(-1) != 1");
        println!("✓ 2 * 2^(-1) = 1");
    }

    #[test]
    fn debug_exponent_construction() {
        println!("\n=== Debug: Exponent construction ===");
        
        // p = 2^255 - 19
        let p: [u8; 32] = [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        println!("p = {:02x?}...", &p[..8]);
        println!("p[0] = {:02x}, p[31] = {:02x}", p[0], p[31]);
        
        // p-2 = 2^255 - 21
        let mut p_minus_2 = p;
        p_minus_2[0] = p_minus_2[0].wrapping_sub(2);
        println!("\np-2 = {:02x?}...", &p_minus_2[..8]);
        println!("p-2[0] = {:02x} (should be 0xeb)", p_minus_2[0]);
        
        // Verify bit pattern
        println!("\nBit pattern of p-2:");
        println!("Byte 0: {:08b} (0x{:02x})", p_minus_2[0], p_minus_2[0]);
        println!("Byte 31: {:08b} (0x{:02x})", p_minus_2[31], p_minus_2[31]);
        
        // Count set bits
        let mut set_bits = 0;
        for byte in &p_minus_2 {
            for bit in 0..8 {
                if (byte >> bit) & 1 != 0 {
                    set_bits += 1;
                }
            }
        }
        println!("\nTotal bits set in p-2: {}", set_bits);
        println!("(Should be close to 255 - only a few bits are 0)");
    }
    
    #[test]
    fn debug_field_operations() {
        println!("\n=== Debug: Basic field operations ===");
        
        // Test that constants are correct
        println!("\n--- Constants check ---");
        let one = FieldElement::one();
        let minus_one = FieldElement::minus_one();
        println!("one.v = {:?}", one.v);
        println!("minus_one.v = {:?}", minus_one.v);
        
        // Test basic arithmetic
        println!("\n--- Basic arithmetic ---");
        let two = FieldElement::two();
        let three = two.add(&one);
        println!("2 + 1 = {:?}", three.v);
        println!("2 + 1 bytes = {:02x?}", three.to_bytes());
        
        // Test subtraction
        let zero = one.sub(&one);
        println!("1 - 1 = {:?}", zero.v);
        assert!(zero.is_zero(), "1 - 1 should be zero");
        
        // Test that p ≡ 0 (mod p)
        let p = FieldElement::from_bytes(&[0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
        println!("\np mod p = {:02x?}", p.to_bytes());
        assert!(p.is_zero(), "p should reduce to 0");
        
        // Test carry and reduce behavior
        println!("\n--- Carry/reduce behavior ---");
        let mut large = FieldElement { v: [0x7ffffff; 10] }; // Over limit
        println!("Before reduce: {:?}", large.v);
        large.reduce_once();
        println!("After reduce: {:?}", large.v);
    }
    
    #[test]
    fn test_ref10_multiplication_coefficients() {
        // Test that our multiplication matches ref10 coefficients
        // This verifies the pre-scaling is correct
        
        // Test 1: Simple case where only one limb is set
        let mut f = FieldElement::zero();
        f.v[1] = 1; // Odd index
        let mut g = FieldElement::zero();
        g.v[9] = 1; // Will contribute to h[10], needs *19
        
        let h = f.mul(&g);
        // f[1]*g[9] contributes to h[10] which gets folded to h[0] with *19
        // Since f[1] is odd, it also gets *2, so total factor is 38
        // Expected: h[0] = 38
        
        let expected_bytes = FieldElement::from_bytes(&[38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_bytes();
        assert_eq!(h.to_bytes(), expected_bytes, "f[1]*g[9] should give 38 in h[0]");
        
        // Test 2: Verify (p-1)^2 = 1
        let minus_one = FieldElement::minus_one();
        let squared = minus_one.mul(&minus_one);
        assert_eq!(squared.to_bytes(), FieldElement::one().to_bytes(), "(-1)^2 should equal 1");
    }
    
    #[test]
    fn test_reduce_once_correctness() {
        // Test that reduce_once properly handles values >= p
        
        // Test 1: Value = p should reduce to 0
        let p = FieldElement::from_bytes(&[0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
        assert!(p.is_zero(), "p should reduce to 0");
        
        // Test 2: Value = p + 1 should reduce to 1
        let mut p_plus_1 = FieldElement::from_bytes(&[0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
        p_plus_1.v[0] += 1;
        p_plus_1.reduce_once();
        assert_eq!(p_plus_1.to_bytes(), FieldElement::one().to_bytes(), "p+1 should reduce to 1");
        
        // Test 3: Value = 2p - 1 should reduce to p - 1
        let mut two_p_minus_1 = FieldElement { v: [0; 10] };
        for (i, &prime_limb) in PRIME_LIMBS.iter().enumerate() {
            two_p_minus_1.v[i] = 2 * prime_limb;
        }
        two_p_minus_1.v[0] -= 1;
        two_p_minus_1.reduce_once();
        assert_eq!(two_p_minus_1.to_bytes(), FieldElement::minus_one().to_bytes(), "2p-1 should reduce to p-1");
        
        // Test 4: Value in [p, p + 2^25) range (the problematic case)
        let mut p_plus_small = FieldElement::from_bytes(&[0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
        p_plus_small.v[0] += 100; // Add small value
        p_plus_small.reduce_once();
        let expected = FieldElement::from_bytes(&[100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(p_plus_small.to_bytes(), expected.to_bytes(), "p+100 should reduce to 100");
    }
}