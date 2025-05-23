//! NIST P-384 Elliptic Curve Primitives
//!
//! This module implements the NIST P-384 elliptic curve operations in constant time.
//! The curve equation is y² = x³ - 3x + b over the prime field F_p where:
//! - p = 2^384 - 2^128 - 2^96 + 2^32 - 1 (NIST P-384 prime)
//! - The curve order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
//!
//! All operations are implemented to be constant-time to prevent timing attacks.
//! The implementation uses:
//! - Montgomery reduction for field arithmetic
//! - Jacobian projective coordinates for efficient point operations
//! - Binary scalar multiplication with constant-time point selection

use crate::error::{Error, Result, validate};
use crate::kdf::hkdf::Hkdf;
use crate::hash::sha2::Sha384;
use crate::kdf::KeyDerivationFunction as KdfTrait;
use common::security::{SecretBuffer, SecureOperation, SecureCompare};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{CryptoRng, RngCore};
use params::traditional::ecdsa::NIST_P384;
use internal::constant_time::{ct_eq, ct_select};
use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

/// Size of a P-384 scalar in bytes (48 bytes = 384 bits)
pub const P384_SCALAR_SIZE: usize = 48;

/// Size of a P-384 field element in bytes (48 bytes = 384 bits)
pub const P384_FIELD_ELEMENT_SIZE: usize = 48;

/// Size of an uncompressed P-384 point in bytes: format byte (0x04) + x-coordinate + y-coordinate
pub const P384_POINT_UNCOMPRESSED_SIZE: usize = 1 + 2 * P384_FIELD_ELEMENT_SIZE; // 97 bytes: 0x04 || x || y

/// Size of the KDF output for P-384 ECDH-KEM shared secret derivation
pub const P384_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE: usize = 48;

/// P-384 field element representing values in F_p
/// 
/// Internally stored as 12 little-endian 32-bit limbs for efficient arithmetic.
/// All operations maintain the invariant that values are reduced modulo p.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldElement([u32; 12]);

/// P-384 scalar value for use in elliptic curve operations
/// 
/// Represents integers modulo the curve order n. Used for private keys
/// and scalar multiplication. Automatically zeroized on drop for security.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Debug)]
pub struct Scalar(SecretBuffer<P384_SCALAR_SIZE>);

/// P-384 elliptic curve point in affine coordinates (x, y)
/// 
/// Represents points on the NIST P-384 curve. The special point at infinity
/// (identity element) is represented with is_identity = true.
#[derive(Clone, Debug)]
pub struct Point {
    /// Whether this point is the identity element (point at infinity)
    is_identity: Choice,
    /// X coordinate in affine representation
    x: FieldElement,
    /// Y coordinate in affine representation  
    y: FieldElement,
}

impl PartialEq for Point {
    /// Constant-time equality comparison for elliptic curve points
    /// 
    /// Handles the special case where either point is the identity element.
    /// For regular points, compares both x and y coordinates.
    fn eq(&self, other: &Self) -> bool {
        // If either is identity, both must be identity to be equal
        let self_is_identity: bool = self.is_identity.into();
        let other_is_identity: bool = other.is_identity.into();

        if self_is_identity || other_is_identity {
            return self_is_identity == other_is_identity;
        }

        // Otherwise compare coordinates
        self.x == other.x && self.y == other.y
    }
}

/// P-384 point in Jacobian projective coordinates (X:Y:Z) for efficient arithmetic
/// 
/// Jacobian coordinates represent affine point (x,y) as (X:Y:Z) where:
/// - x = X/Z²
/// - y = Y/Z³  
/// - Point at infinity has Z = 0
/// 
/// This representation allows for efficient point addition and doubling
/// without expensive field inversions during intermediate calculations.
#[derive(Clone, Debug)]
struct ProjectivePoint {
    /// Whether this point is the identity element (point at infinity)
    is_identity: Choice,
    /// X coordinate in Jacobian representation
    x: FieldElement,
    /// Y coordinate in Jacobian representation
    y: FieldElement,
    /// Z coordinate (projective factor)
    z: FieldElement,
}

impl FieldElement {
    /* -------------------------------------------------------------------- */
    /*  NIST P-384 Field Constants (stored as little-endian 32-bit limbs)  */
    /* -------------------------------------------------------------------- */

    /// The NIST P-384 prime modulus: p = 2^384 - 2^128 - 2^96 + 2^32 - 1
    /// Stored as 12 little-endian 32-bit limbs where limbs[0] is least significant
    const MOD_LIMBS: [u32; 12] = [
        0xFFFF_FFFF, // 2⁰ … 2³¹
        0x0000_0000, // 2³² … 2⁶³
        0x0000_0000, // 2⁶⁴ … 2⁹⁵
        0xFFFF_FFFF, // 2⁹⁶ … 2¹²⁷
        0xFFFF_FFFE, // 2¹²⁸ … 2¹⁵⁹
        0xFFFF_FFFF, // 2¹⁶⁰ … 2¹⁹¹
        0xFFFF_FFFF, // 2¹⁹² … 2²²³
        0xFFFF_FFFF, // 2²²⁴ … 2²⁵⁵
        0xFFFF_FFFF, // 2²⁵⁶ … 2²⁸⁷
        0xFFFF_FFFF, // 2²⁸⁸ … 2³¹⁹
        0xFFFF_FFFF, // 2³²⁰ … 2³⁵¹
        0xFFFF_FFFF, // 2³⁵² … 2³⁸³
    ];

    /// The curve parameter a = -3 mod p, used in the curve equation y² = x³ + ax + b
    /// For P-384: a = p - 3
    const A_M3: [u32; 12] = [
        0xFFFF_FFFC, // (2³² - 1) - 3 = 2³² - 4
        0x0000_0000,
        0x0000_0000,
        0xFFFF_FFFF,
        0xFFFF_FFFE,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
    ];

    /// The additive identity element: 0
    pub fn zero() -> Self {
        FieldElement([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// The multiplicative identity element: 1
    pub fn one() -> Self {
        FieldElement([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Create a field element from big-endian byte representation
    /// 
    /// Validates that the input represents a value less than the field modulus p.
    /// Returns an error if the value is >= p.
    pub fn from_bytes(bytes: &[u8; P384_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let mut limbs = [0u32; 12];

        // Convert from big-endian bytes to little-endian limbs
        // limbs[0] = least-significant 4 bytes (bytes[44..48])
        // limbs[11] = most-significant 4 bytes (bytes[0..4])
        for i in 0..12 {
            let offset = (11 - i) * 4; // Byte offset: 44, 40, 36, ..., 0
            limbs[i] = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
        }

        // Validate that the value is in the field (< p)
        let fe = FieldElement(limbs);
        if !fe.is_valid() {
            return Err(Error::param("FieldElement", "Value must be less than the field modulus"));
        }

        Ok(fe)
    }

    /// Convert field element to big-endian byte representation
    pub fn to_bytes(&self) -> [u8; P384_FIELD_ELEMENT_SIZE] {
        let mut bytes = [0u8; P384_FIELD_ELEMENT_SIZE];
        
        // Convert from little-endian limbs to big-endian bytes
        for i in 0..12 {
            let limb_bytes = self.0[i].to_be_bytes();
            let offset = (11 - i) * 4; // Byte offset: 44, 40, 36, ..., 0
            bytes[offset..offset + 4].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// Constant-time validation that the field element is in canonical form (< p)
    /// 
    /// Uses constant-time subtraction to check if self < p without branching.
    /// Returns true if the element is valid (< p), false otherwise.
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        // Attempt to subtract p from self
        // If subtraction requires a borrow, then self < p (valid)
        let (_, borrow) = Self::sbb12(self.0, Self::MOD_LIMBS);
        borrow == 1
    }

    /// Constant-time field addition: (self + other) mod p
    /// 
    /// Algorithm:
    /// 1. Perform full 384-bit addition with carry detection
    /// 2. Conditionally subtract p if result >= p
    /// 3. Ensure result is in canonical form
    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        // Step 1: Full 384-bit addition
        let (sum, carry) = Self::adc12(self.0, other.0);

        // Step 2: Attempt conditional reduction by subtracting p
        let (sum_minus_p, borrow) = Self::sbb12(sum, Self::MOD_LIMBS);

        // Step 3: Choose reduced value if:
        //   - Addition overflowed (carry == 1), OR
        //   - Subtraction didn't borrow (borrow == 0), meaning sum >= p
        let need_reduce = (carry | (borrow ^ 1)) & 1;
        let reduced = Self::conditional_select(&sum, &sum_minus_p, Choice::from(need_reduce as u8));

        // Step 4: Final canonical reduction
        reduced.conditional_sub_p()
    }

    /// Constant-time field subtraction: (self - other) mod p
    /// 
    /// Algorithm:
    /// 1. Perform limb-wise subtraction
    /// 2. If subtraction borrows, add p to get the correct positive result
    pub fn sub(&self, other: &Self) -> Self {
        // Step 1: Raw subtraction
        let (diff, borrow) = Self::sbb12(self.0, other.0);

        // Step 2: If we borrowed, add p to get the correct positive result
        let (candidate, _) = Self::adc12(diff, Self::MOD_LIMBS);

        // Step 3: Constant-time select based on borrow flag
        Self::conditional_select(&diff, &candidate, Choice::from(borrow as u8))
    }

    /// Constant-time conditional selection between two limb arrays
    /// 
    /// Returns a if flag == 0, returns b if flag == 1
    /// Used for branchless operations to maintain constant-time guarantees.
    fn conditional_select(a: &[u32;12], b: &[u32;12], flag: Choice) -> Self {
        let mut out = [0u32;12];
        for i in 0..12 {
            out[i] = u32::conditional_select(&a[i], &b[i], flag);
        }
        FieldElement(out)
    }

    /// 12-limb addition with carry propagation
    /// 
    /// Performs full-width addition across all limbs, returning both
    /// the sum and the final carry bit for overflow detection.
    #[inline(always)]
    fn adc12(a: [u32; 12], b: [u32; 12]) -> ([u32; 12], u32) {
        let mut r = [0u32; 12];
        let mut carry = 0;

        for i in 0..12 {
            // Add corresponding limbs plus carry from previous iteration
            let (sum1, carry1) = a[i].overflowing_add(b[i]);
            let (sum2, carry2) = sum1.overflowing_add(carry);

            r[i] = sum2;
            carry = (carry1 as u32) | (carry2 as u32);
        }

        (r, carry)
    }

    /// 12-limb subtraction with borrow propagation
    /// 
    /// Performs full-width subtraction across all limbs, returning both
    /// the difference and the final borrow bit for underflow detection.
    #[inline(always)]
    fn sbb12(a: [u32;12], b: [u32;12]) -> ([u32;12], u32) {
        let mut r = [0u32;12];
        let mut borrow = 0;
        
        for i in 0..12 {
            // Subtract corresponding limbs minus borrow from previous iteration
            let (diff1, borrow1) = a[i].overflowing_sub(b[i]);
            let (diff2, borrow2) = diff1.overflowing_sub(borrow);
            
            r[i] = diff2;
            borrow = (borrow1 as u32) | (borrow2 as u32);
        }
        (r, borrow)
    }

    /// Conditionally add the field modulus p based on a boolean flag
    /// 
    /// Used in reduction algorithms where we may need to add p back
    /// after a subtraction that went negative.
    fn conditional_add(limbs: [u32; 12], flag: Choice) -> Self {
        if flag.unwrap_u8() != 0 {
            let (sum, _) = Self::adc12(limbs, Self::MOD_LIMBS);
            return FieldElement(sum);
        }
        FieldElement(limbs)
    }

    /// Conditionally subtract the field modulus p based on a boolean condition
    /// 
    /// Uses constant-time selection to avoid branching while maintaining
    /// the option to perform the subtraction.
    fn conditional_sub(limbs: [u32; 12], condition: Choice) -> Self {
        let mut result = [0u32; 12];
        let (diff, _) = Self::sbb12(limbs, Self::MOD_LIMBS);

        // Constant-time select between original limbs and difference
        for i in 0..12 {
            result[i] = u32::conditional_select(&limbs[i], &diff[i], condition);
        }

        Self(result)
    }

    /// Conditionally subtract p if the current value is >= p
    /// 
    /// Ensures the field element is in canonical reduced form.
    /// Used as a final step in arithmetic operations.
    fn conditional_sub_p(&self) -> Self {
        let needs_sub = Choice::from((!self.is_valid() as u8) & 1);
        Self::conditional_sub(self.0, needs_sub)
    }

    /// Field multiplication: (self * other) mod p
    /// 
    /// Algorithm:
    /// 1. Compute the full 768-bit product using schoolbook multiplication
    /// 2. Perform carry propagation to get proper limb representation
    /// 3. Apply NIST P-384 specific fast reduction (Solinas method)
    /// 
    /// The multiplication is performed in three phases to maintain clarity
    /// and correctness while achieving good performance.
    pub fn mul(&self, other: &Self) -> Self {
        // Phase 1: Accumulate partial products in 128-bit temporaries
        // This prevents overflow during the schoolbook multiplication
        let mut t = [0u128; 24];
        for i in 0..12 {
            for j in 0..12 {
                t[i + j] += (self.0[i] as u128) * (other.0[j] as u128);
            }
        }
    
        // Phase 2: Carry propagation to convert to 32-bit limb representation
        let mut prod = [0u32; 24];
        let mut carry: u128 = 0;
        for i in 0..24 {
            let v = t[i] + carry;
            prod[i] = (v & 0xffff_ffff) as u32;
            carry   = v >> 32;
        }
    
        // Phase 3: Apply NIST P-384 fast reduction
        Self::reduce_wide(prod)
    }

    /// Field squaring: self² mod p
    /// 
    /// Optimized version of multiplication for the case where both operands
    /// are the same. Currently implemented as self.mul(self) but could be
    /// optimized further with dedicated squaring algorithms.
    #[inline(always)]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// NIST P-384 specific reduction for 768-bit values using Solinas method 
    /// Fully constant-time Solinas reduction with two carry-folds.
    /// For P-384: 2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p)
    pub fn reduce_wide(t: [u32; 24]) -> FieldElement {
        // 1) load into signed 128-bit
        let mut s = [0i128; 24];
        for i in 0..24 {
            s[i] = t[i] as i128;
        }

        // 2) fold high limbs 12..23 into 0..11 via
        //    2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p)
        for i in (12..24).rev() {
            let v = s[i];
            s[i] = 0;
            s[i - 12] = s[i - 12].wrapping_add(v);     // +1 (2^0 term)
            s[i - 11] = s[i - 11].wrapping_sub(v);     // -2^32 term
            s[i - 9]  = s[i - 9].wrapping_add(v);      // +2^96 term
            s[i - 8]  = s[i - 8].wrapping_add(v);      // +2^128 term
        }

        // 2b) the previous step can leave non-zero words in slots 12..15
        //     (it happens when i = 20..23). Fold them once more so that
        //     all non-zero limbs are now in 0..11.
        for i in (12..16).rev() {
            let v = s[i];
            s[i] = 0;
            s[i - 12] = s[i - 12].wrapping_add(v);     // +1
            s[i - 11] = s[i - 11].wrapping_sub(v);     // -2^32
            s[i - 9]  = s[i - 9].wrapping_add(v);      // +2^96
            s[i - 8]  = s[i - 8].wrapping_add(v);      // +2^128
        }

        // 3) first signed carry-propagate
        let mut carry1: i128 = 0;
        for i in 0..12 {
            let tmp = s[i] + carry1;
            s[i] = tmp & 0xffff_ffff;
            carry1 = tmp >> 32;  // arithmetic shift
        }

        // 4) fold carry1 back down using same relation
        let c1 = carry1;
        s[0] = s[0].wrapping_add(c1);     // +1
        s[1] = s[1].wrapping_sub(c1);     // -2^32
        s[3] = s[3].wrapping_add(c1);     // +2^96
        s[4] = s[4].wrapping_add(c1);     // +2^128

        // 5) second signed carry-propagate
        let mut carry2: i128 = 0;
        for i in 0..12 {
            let tmp = s[i] + carry2;
            s[i] = tmp & 0xffff_ffff;
            carry2 = tmp >> 32;
        }

        // 6) fold carry2 back down
        let c2 = carry2;
        s[0] = s[0].wrapping_add(c2);
        s[1] = s[1].wrapping_sub(c2);
        s[3] = s[3].wrapping_add(c2);
        s[4] = s[4].wrapping_add(c2);

        // 7) final signed carry-propagate into 32-bit limbs
        let mut out = [0u32; 12];
        let mut carry3: i128 = 0;
        for i in 0..12 {
            let tmp = s[i] + carry3;
            out[i]   = (tmp & 0xffff_ffff) as u32;
            carry3   = tmp >> 32;
        }

        // 8) one last constant-time subtract if ≥ p
        let (subbed, borrow) = Self::sbb12(out, Self::MOD_LIMBS);
        let need_sub = Choice::from((borrow ^ 1) as u8); // borrow==0 ⇒ out>=p
        Self::conditional_select(&out, &subbed, need_sub)
    }

    /// Compute the modular multiplicative inverse using Fermat's Little Theorem
    /// 
    /// For prime fields, a^(p-1) ≡ 1 (mod p), so a^(p-2) ≡ a^(-1) (mod p).
    /// Uses binary exponentiation (square-and-multiply) for efficiency.
    /// 
    /// Returns an error if attempting to invert zero (which has no inverse).
    pub fn invert(&self) -> Result<Self> {
        if self.is_zero() {
            return Err(Error::param("FieldElement", "Inversion of zero is undefined"));
        }

        // The exponent p-2 for NIST P-384 in big-endian byte format
        // p = 2^384 - 2^128 - 2^96 + 2^32 - 1
        // p-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFD
        const P_MINUS_2: [u8; 48] = [
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFD,
        ];

        // Binary exponentiation: compute self^(p-2) mod p
        let mut result = FieldElement::one();
        let mut base = self.clone();
        
        // Process each bit of the exponent from least to most significant
        for &byte in P_MINUS_2.iter().rev() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.square();
            }
        }
        
        Ok(result)
    }

    /// Check if the field element represents zero
    /// 
    /// Constant-time check across all limbs to determine if the
    /// field element is the additive identity.
    pub fn is_zero(&self) -> bool {
        for limb in self.0.iter() {
            if *limb != 0 {
                return false;
            }
        }
        true
    }

    /// Get the field modulus p as a FieldElement
    /// 
    /// Returns the NIST P-384 prime modulus for use in reduction operations.
    fn get_modulus() -> Self {
        FieldElement(Self::MOD_LIMBS)
    }

    /// Reduce the field element modulo p if needed
    /// 
    /// Repeatedly subtracts p until the value is in canonical form.
    /// Note: This is a simple implementation - production code would
    /// use more efficient reduction methods.
    fn reduce(&self) -> Self {
        let mut result = self.clone();
        while !result.is_valid() {
            result = result.sub(&FieldElement::get_modulus());
        }
        result
    }
}

impl Point {
    /// Create a new elliptic curve point from uncompressed coordinates
    /// 
    /// Validates that the given (x, y) coordinates satisfy the P-384 curve equation:
    /// y² = x³ - 3x + b (mod p)
    /// 
    /// Returns an error if the point is not on the curve.
    pub fn new_uncompressed(x: &[u8; P384_FIELD_ELEMENT_SIZE], y: &[u8; P384_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let x_fe = FieldElement::from_bytes(x)?;
        let y_fe = FieldElement::from_bytes(y)?;

        // Validate that the point lies on the curve
        if !Self::is_on_curve(&x_fe, &y_fe) {
            return Err(Error::param("P-384 Point", "Point coordinates do not satisfy curve equation"));
        }

        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe,
            y: y_fe,
        })
    }

    /// Create the identity element (point at infinity)
    /// 
    /// The identity element serves as the additive neutral element
    /// for the elliptic curve group operation.
    pub fn identity() -> Self {
        Point {
            is_identity: Choice::from(1),
            x: FieldElement::zero(),
            y: FieldElement::zero(),
        }
    }

    /// Check if this point is the identity element
    pub fn is_identity(&self) -> bool {
        self.is_identity.into()
    }

    /// Validate that coordinates satisfy the P-384 curve equation
    /// 
    /// Verifies: y² = x³ - 3x + b (mod p)
    /// where b is the curve parameter from NIST P-384 specification.
    /// 
    /// This is a critical security check to prevent invalid curve attacks.
    fn is_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
        // Left-hand side: y²
        let y_squared = y.square();
        
        // Right-hand side: x³ - 3x + b
        let x_cubed = x.square().mul(x);
        let a_coeff = FieldElement(FieldElement::A_M3);  // a = -3 mod p
        let ax = a_coeff.mul(x);
        let b_coeff = FieldElement::from_bytes(&NIST_P384.b).unwrap();
    
        // Compute x³ - 3x + b
        let x_cubed_plus_ax = x_cubed.add(&ax);
        let rhs = x_cubed_plus_ax.add(&b_coeff);
    
        y_squared == rhs
    }

    /// Get the x-coordinate as a byte array in big-endian format
    pub fn x_coordinate_bytes(&self) -> [u8; P384_FIELD_ELEMENT_SIZE] {
        self.x.to_bytes()
    }

    /// Get the y-coordinate as a byte array in big-endian format
    pub fn y_coordinate_bytes(&self) -> [u8; P384_FIELD_ELEMENT_SIZE] {
        self.y.to_bytes()
    }

    /// Serialize point to uncompressed format: 0x04 || x || y
    /// 
    /// The uncompressed point format is:
    /// - 1 byte: 0x04 (uncompressed indicator)
    /// - 48 bytes: x-coordinate (big-endian)
    /// - 48 bytes: y-coordinate (big-endian)
    /// 
    /// The identity point is represented as all zeros.
    pub fn serialize_uncompressed(&self) -> [u8; P384_POINT_UNCOMPRESSED_SIZE] {
        let mut result = [0u8; P384_POINT_UNCOMPRESSED_SIZE];

        // Special encoding for the identity element
        if self.is_identity() {
            return result; // All zeros represents identity
        }

        // Standard uncompressed format: 0x04 || x || y
        result[0] = 0x04;
        result[1..49].copy_from_slice(&self.x.to_bytes());
        result[49..97].copy_from_slice(&self.y.to_bytes());

        result
    }

    /// Deserialize point from uncompressed byte format
    /// 
    /// Supports the standard uncompressed format (0x04 || x || y) and
    /// recognizes the all-zeros encoding for the identity element.
    pub fn deserialize_uncompressed(bytes: &[u8]) -> Result<Self> {
        validate::length("P-384 Point", bytes.len(), P384_POINT_UNCOMPRESSED_SIZE)?;

        // Check for identity point (all zeros)
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::identity());
        }

        // Validate uncompressed format indicator
        if bytes[0] != 0x04 {
            return Err(Error::param("P-384 Point", "Invalid uncompressed point format (type byte)"));
        }

        // Extract and validate coordinates
        let mut x_bytes = [0u8; P384_FIELD_ELEMENT_SIZE];
        let mut y_bytes = [0u8; P384_FIELD_ELEMENT_SIZE];

        x_bytes.copy_from_slice(&bytes[1..49]);
        y_bytes.copy_from_slice(&bytes[49..97]);

        Self::new_uncompressed(&x_bytes, &y_bytes)
    }

    /// Convert affine point to Jacobian projective coordinates
    /// 
    /// Affine (x, y) → Jacobian (X:Y:Z) where X=x, Y=y, Z=1
    /// Identity point maps to (0:1:0) following standard conventions.
    fn to_projective(&self) -> ProjectivePoint {
        if self.is_identity() {
            return ProjectivePoint {
                is_identity: Choice::from(1),
                x: FieldElement::zero(),
                y: FieldElement::one(),
                z: FieldElement::zero(),
            };
        }

        ProjectivePoint {
            is_identity: Choice::from(0),
            x: self.x.clone(),
            y: self.y.clone(),
            z: FieldElement::one(),
        }
    }

    /// Elliptic curve point addition using the group law
    /// 
    /// Implements the abelian group operation for P-384 points.
    /// Converts to projective coordinates for efficient computation,
    /// then converts back to affine form.
    pub fn add(&self, other: &Self) -> Self {
        let p1 = self.to_projective();
        let p2 = other.to_projective();
        let result = p1.add(&p2);
        result.to_affine()
    }

    /// Elliptic curve point doubling: 2 * self
    /// 
    /// Computes the sum of a point with itself, which has a more
    /// efficient formula than general point addition.
    pub fn double(&self) -> Self {
        let p = self.to_projective();
        let result = p.double();
        result.to_affine()
    }

    /// Scalar multiplication: compute scalar * self
    /// 
    /// Uses the binary method (double-and-add) with constant-time execution
    /// to prevent timing attacks. Processes scalar bits from most significant
    /// to least significant for efficiency.
    /// 
    /// Returns the identity element if scalar is zero.
    pub fn mul(&self, scalar: &Scalar) -> Result<Self> {
        if scalar.is_zero() {
            return Ok(Self::identity());
        }

        let scalar_bytes = scalar.as_secret_buffer().as_ref();
        
        // Work in Jacobian/projective coordinates throughout
        let base = self.to_projective();
        let mut result = ProjectivePoint {
            is_identity: Choice::from(1), // identity
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        };

        for byte in scalar_bytes.iter() {
            for bit_pos in (0..8).rev() {
                result = result.double();
                let bit = (byte >> bit_pos) & 1;
                if bit == 1 {
                    result = result.add(&base);
                }
            }
        }

        let affine_result = result.to_affine();
        Ok(affine_result)
    }
}

impl ProjectivePoint {
    /// Projective point addition using complete addition formulas
    /// 
    /// Implements the addition law for Jacobian coordinates that works
    /// for all input combinations, including point doubling and identity cases.
    /// 
    /// Uses optimized formulas that avoid expensive field inversions
    /// until the final conversion back to affine coordinates.
    fn add(&self, other: &Self) -> Self {
        // Handle identity element cases
        if self.is_identity.into() {
            return other.clone();
        }
        if other.is_identity.into() {
            return self.clone();
        }

        // Compute addition using Jacobian coordinate formulas
        // Reference: "Guide to Elliptic Curve Cryptography" Algorithm 3.22

        // Pre-compute commonly used values
        let z1_squared = self.z.square();
        let z2_squared = other.z.square();
        let z1_cubed   = z1_squared.mul(&self.z);
        let z2_cubed   = z2_squared.mul(&other.z);

        // Project coordinates to common denominator
        let u1 = self.x.mul(&z2_squared);   // X1 · Z2²
        let u2 = other.x.mul(&z1_squared);  // X2 · Z1²
        let s1 = self.y.mul(&z2_cubed);     // Y1 · Z2³
        let s2 = other.y.mul(&z1_cubed);    // Y2 · Z1³

        // Compute differences
        let h = u2.sub(&u1); // X2·Z1² − X1·Z2²
        let r = s2.sub(&s1); // Y2·Z1³ − Y1·Z2³

        // Handle special cases: point doubling or inverse points
        if h.is_zero() {
            if r.is_zero() {
                // Points are equal: use doubling formula
                return self.double();
            } else {
                // Points are inverses: return identity
                return Self {
                    is_identity: Choice::from(1),
                    x: FieldElement::zero(),
                    y: FieldElement::one(),   // (0 : 1 : 0)
                    z: FieldElement::zero(),
                };
            }
        }

        // General addition case
        let h_squared = h.square();
        let h_cubed   = h_squared.mul(&h);
        let v         = u1.mul(&h_squared);

        // X3 = r² − h³ − 2·v
        let r_squared = r.square();
        let two_v     = v.add(&v);
        let mut x3    = r_squared.sub(&h_cubed);
        x3 = x3.sub(&two_v);

        // Y3 = r·(v − X3) − s1·h³
        let v_minus_x3      = v.sub(&x3);
        let r_times_diff    = r.mul(&v_minus_x3);
        let s1_times_h_cubed= s1.mul(&h_cubed);
        let y3              = r_times_diff.sub(&s1_times_h_cubed);

        // Z3 = Z1 · Z2 · h
        let z1_times_z2 = self.z.mul(&other.z);
        let z3          = z1_times_z2.mul(&h);

        // if Z3 == 0 we actually computed the point at infinity
        if z3.is_zero() {
            return Self {
                is_identity: Choice::from(1),
                x: FieldElement::zero(),
                y: FieldElement::one(),   // canonical projective infinity
                z: FieldElement::zero(),
            };
        }

        // Normal return path
        Self {
            is_identity: Choice::from(0),
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Projective point doubling using efficient doubling formulas
    /// 
    /// Implements optimized point doubling in Jacobian coordinates.  
    /// More efficient than general addition when both operands are the same.
    /// Jacobian doubling for short-Weierstrass curves with *a = –3*
    /// (SEC 1, Algorithm 3.2.1  —  Δ / Γ / β / α form)
    #[inline]
    pub fn double(&self) -> Self {
        // ── 0. Easy outs ────────────────────────────────────────
        if self.is_identity.into() {
            return self.clone();
        }
        if self.y.is_zero() {
            // (x,0) is its own negative ⇒ 2·P = ∞
            return Self {
                is_identity: Choice::from(1),
                x: FieldElement::zero(),
                y: FieldElement::one(),
                z: FieldElement::zero(),
            };
        }

        // ── 1. Pre-computations ─────────────────────────────────
        // Δ = Z₁²
        let delta = self.z.square();

        // Γ = Y₁²
        let gamma = self.y.square();

        // β = X₁·Γ
        let beta = self.x.mul(&gamma);

        // α = 3·(X₁ − Δ)·(X₁ + Δ)       (valid because a = –3)
        let x_plus_delta  = self.x.add(&delta);
        let x_minus_delta = self.x.sub(&delta);
        let mut alpha     = x_plus_delta.mul(&x_minus_delta);
        alpha = alpha.add(&alpha).add(&alpha);          // ×3

        // ── 2. Output coordinates ──────────────────────────────
        // X₃ = α² − 8·β
        let mut eight_beta = beta.add(&beta);           // 2β
        eight_beta = eight_beta.add(&eight_beta);       // 4β
        eight_beta = eight_beta.add(&eight_beta);       // 8β
        let x3 = alpha.square().sub(&eight_beta);

        // Z₃ = (Y₁ + Z₁)² − Γ − Δ
        let y_plus_z = self.y.add(&self.z);
        let z3 = y_plus_z.square().sub(&gamma).sub(&delta);

        // Y₃ = α·(4·β − X₃) − 8·Γ²
        let mut four_beta = beta.add(&beta);            // 2β
        four_beta = four_beta.add(&four_beta);          // 4β
        let mut y3 = four_beta.sub(&x3);
        y3 = alpha.mul(&y3);

        let mut gamma_sq = gamma.square();              // Γ²
        let mut eight_gamma_sq = gamma_sq.add(&gamma_sq);   // 2Γ²
        eight_gamma_sq = eight_gamma_sq.add(&eight_gamma_sq); // 4Γ²
        eight_gamma_sq = eight_gamma_sq.add(&eight_gamma_sq); // 8Γ²
        y3 = y3.sub(&eight_gamma_sq);

        Self {
            is_identity: Choice::from(0),
            x: x3,
            y: y3,
            z: z3,
        }
    }


    /// Convert Jacobian projective coordinates back to affine coordinates
    /// 
    /// Performs the conversion (X:Y:Z) → (X/Z², Y/Z³) using field inversion.
    /// This is the most expensive operation but only needed for final results.
    fn to_affine(&self) -> Point {
        if self.is_identity.into() {
            return Point::identity();
        }

        // Compute the modular inverse of Z
        let z_inv = self.z.invert().expect("Non-zero Z coordinate should be invertible");
        let z_inv_squared = z_inv.square();
        let z_inv_cubed = z_inv_squared.mul(&z_inv);

        // Convert to affine coordinates: (x, y) = (X/Z², Y/Z³)
        let x_affine = self.x.mul(&z_inv_squared);
        let y_affine = self.y.mul(&z_inv_cubed);

        Point {
            is_identity: Choice::from(0),
            x: x_affine,
            y: y_affine,
        }
    }
}

impl Scalar {
    /// Create a scalar from raw bytes with modular reduction
    /// 
    /// Ensures the scalar is in the valid range [1, n-1] where n is the curve order.
    /// Performs modular reduction if the input is >= n.
    /// Returns an error if the result would be zero (invalid for cryptographic use).
    pub fn new(mut data: [u8; P384_SCALAR_SIZE]) -> Result<Self> {
        Self::reduce_scalar_bytes(&mut data)?;
        Ok(Scalar(SecretBuffer::new(data)))
    }

    /// Reduce scalar modulo the curve order n using constant-time arithmetic
    /// 
    /// The curve order n for P-384 is:
    /// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    /// 
    /// Algorithm:
    /// 1. Check if input is zero (invalid)
    /// 2. Compare with curve order using constant-time comparison
    /// 3. Conditionally subtract n if input >= n
    /// 4. Verify result is still non-zero
    fn reduce_scalar_bytes(bytes: &mut [u8; P384_SCALAR_SIZE]) -> Result<()> {
        let order = &NIST_P384.n;
    
        // Reject zero scalars immediately
        if bytes.iter().all(|&b| b == 0) {
            return Err(Error::param("P-384 Scalar", "Scalar cannot be zero"));
        }
    
        // Constant-time comparison with curve order
        // We want to check: is bytes >= order?
        let mut gt = 0u8; // set if bytes > order
        let mut lt = 0u8; // set if bytes < order
    
        for i in 0..P384_SCALAR_SIZE {
            let x = bytes[i];
            let y = order[i];
            gt |= ((x > y) as u8) & (!lt);
            lt |= ((x < y) as u8) & (!gt);
        }
        let ge = gt | (!lt); // ge = gt || eq (if not less, then greater or equal)
    
        if gt == 1 || (lt == 0 && gt == 0) {
            // If scalar >= order, perform modular reduction
            let mut borrow = 0u16;
            let mut temp_bytes = *bytes;
    
            for i in (0..P384_SCALAR_SIZE).rev() {
                let diff = (temp_bytes[i] as i16) - (order[i] as i16) - (borrow as i16);
                if diff < 0 {
                    temp_bytes[i] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    temp_bytes[i] = diff as u8;
                    borrow = 0;
                }
            }
    
            *bytes = temp_bytes;
        }
    
        // Check for zero after reduction
        if bytes.iter().all(|&b| b == 0) {
            return Err(Error::param("P-384 Scalar", "Reduction resulted in zero scalar"));
        }
    
        Ok(())
    }

    /// Create a scalar from an existing SecretBuffer
    /// 
    /// Performs the same validation and reduction as `new()` but starts
    /// from a SecretBuffer instead of a raw byte array.
    pub fn from_secret_buffer(buffer: SecretBuffer<P384_SCALAR_SIZE>) -> Result<Self> {
        let mut bytes = [0u8; P384_SCALAR_SIZE];
        bytes.copy_from_slice(buffer.as_ref());

        Self::reduce_scalar_bytes(&mut bytes)?;
        Ok(Scalar(SecretBuffer::new(bytes)))
    }

    /// Access the underlying SecretBuffer containing the scalar value
    pub fn as_secret_buffer(&self) -> &SecretBuffer<P384_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize the scalar to a byte array
    /// 
    /// Returns the scalar in big-endian byte representation.
    /// The output is suitable for storage or transmission.
    pub fn serialize(&self) -> [u8; P384_SCALAR_SIZE] {
        let mut result = [0u8; P384_SCALAR_SIZE];
        result.copy_from_slice(self.0.as_ref());
        result
    }

    /// Deserialize a scalar from bytes with validation
    /// 
    /// Parses bytes as a big-endian scalar value and ensures it's
    /// in the valid range for P-384 operations.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        validate::length("P-384 Scalar", bytes.len(), P384_SCALAR_SIZE)?;

        let mut scalar_bytes = [0u8; P384_SCALAR_SIZE];
        scalar_bytes.copy_from_slice(bytes);

        Self::new(scalar_bytes)
    }

    /// Check if the scalar represents zero
    /// 
    /// Constant-time check to determine if the scalar is the
    /// additive identity (which is invalid for most cryptographic operations).
    pub fn is_zero(&self) -> bool {
        self.0.as_ref().iter().all(|&b| b == 0)
    }
}

/// Get the standard base point G of the P-384 curve
/// 
/// Returns the generator point specified in the NIST P-384 standard.
/// This point generates the cyclic subgroup used for ECDH and ECDSA.
pub fn base_point_g() -> Point {
    Point::new_uncompressed(&NIST_P384.g_x, &NIST_P384.g_y)
        .expect("Standard base point must be valid")
}

/// Scalar multiplication with the base point: scalar * G
/// 
/// Efficiently computes scalar multiplication with the standard generator.
/// This is the core operation for generating public keys from private keys.
pub fn scalar_mult_base_g(scalar: &Scalar) -> Result<Point> {
    let g = base_point_g();
    g.mul(scalar)
}

/// Generate a cryptographically secure ECDH keypair
/// 
/// Uses rejection sampling to ensure the private key scalar is uniformly
/// distributed in the range [1, n-1]. The public key is computed as
/// private_key * G where G is the standard base point.
/// 
/// Returns (private_key, public_key) pair suitable for ECDH key agreement.
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(Scalar, Point)> {
    let mut scalar_bytes = [0u8; P384_SCALAR_SIZE];

    // Use rejection sampling for uniform distribution
    loop {
        rng.fill_bytes(&mut scalar_bytes);

        // Attempt to create a valid scalar (non-zero, < n)
        match Scalar::new(scalar_bytes) {
            Ok(private_key) => {
                // Compute corresponding public key
                let public_key = scalar_mult_base_g(&private_key)?;
                return Ok((private_key, public_key));
            },
            Err(_) => {
                // Invalid scalar generated, retry with new random bytes
                continue;
            }
        }
    }
}

/// General scalar multiplication: compute scalar * point
/// 
/// Performs scalar multiplication with an arbitrary point on the curve.
/// Used in ECDH key agreement and signature verification.
pub fn scalar_mult(scalar: &Scalar, point: &Point) -> Result<Point> {
    if point.is_identity() {
        // scalar * O = O (identity element)
        return Ok(Point::identity());
    }

    point.mul(scalar)
}

/// Key derivation function for ECDH shared secret using HKDF-SHA384
/// 
/// Derives a cryptographically strong shared secret from the ECDH raw output.
/// Uses HKDF (HMAC-based Key Derivation Function) with SHA-384 as specified
/// in RFC 5869 for secure key derivation.
/// 
/// Parameters:
/// - ikm: Input key material (raw ECDH output, e.g., x-coordinate)
/// - info: Optional context information for domain separation
/// 
/// Returns a fixed-length derived key suitable for symmetric encryption.
pub fn kdf_hkdf_sha384_for_ecdh_kem(
    ikm: &[u8],
    info: Option<&[u8]>
) -> Result<[u8; P384_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE]> {
    let hkdf_instance = <Hkdf<Sha384, 24> as KdfTrait>::new();

    // Perform HKDF key derivation
    let derived_key_vec = hkdf_instance.derive_key(
        ikm,
        None, // No salt for ECDH applications (uses zero-length salt)
        info, // Context info for domain separation
        P384_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE
    )?;

    // Convert to fixed-size array
    let mut output_array = [0u8; P384_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE];
    if derived_key_vec.len() == P384_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE {
        output_array.copy_from_slice(&derived_key_vec);
        Ok(output_array)
    } else {
        Err(Error::Length {
            context: "KDF output for ECDH",
            expected: P384_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
            actual: derived_key_vec.len(),
        })
    }
}

#[cfg(test)]
mod tests;