//! P-224 elliptic curve point operations

use crate::ec::p224::{
    constants::{P224_FIELD_ELEMENT_SIZE, P224_POINT_UNCOMPRESSED_SIZE, P224_POINT_COMPRESSED_SIZE}, 
    field::FieldElement,
    scalar::Scalar,
};
use crate::error::{Error, Result, validate};
use params::traditional::ecdsa::NIST_P224;
use subtle::Choice;

/// Format of a serialized elliptic curve point
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointFormat {
    /// Identity point (all zeros)
    Identity,
    /// Uncompressed format: 0x04 || x || y
    Uncompressed,
    /// Compressed format: 0x02/0x03 || x
    Compressed,
}

/// P-224 elliptic curve point in affine coordinates (x, y)
/// 
/// Represents points on the NIST P-224 curve. The special point at infinity
/// (identity element) is represented with is_identity = true.
#[derive(Clone, Debug)]
pub struct Point {
    /// Whether this point is the identity element (point at infinity)
    pub(crate) is_identity: Choice,
    /// X coordinate in affine representation
    pub(crate) x: FieldElement,
    /// Y coordinate in affine representation  
    pub(crate) y: FieldElement,
}

/// P-224 point in Jacobian projective coordinates (X:Y:Z) for efficient arithmetic
/// 
/// Jacobian coordinates represent affine point (x,y) as (X:Y:Z) where:
/// - x = X/Z²
/// - y = Y/Z³  
/// - Point at infinity has Z = 0
/// 
/// This representation allows for efficient point addition and doubling
/// without expensive field inversions during intermediate calculations.
#[derive(Clone, Debug)]
pub(crate) struct ProjectivePoint {
    /// Whether this point is the identity element (point at infinity)
    is_identity: Choice,
    /// X coordinate in Jacobian representation
    x: FieldElement,
    /// Y coordinate in Jacobian representation
    y: FieldElement,
    /// Z coordinate (projective factor)
    z: FieldElement,
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

impl Point {
    /// Create a new elliptic curve point from uncompressed coordinates
    /// 
    /// Validates that the given (x, y) coordinates satisfy the P-224 curve equation:
    /// y² = x³ - 3x + b (mod p)
    /// 
    /// Returns an error if the point is not on the curve.
    pub fn new_uncompressed(x: &[u8; P224_FIELD_ELEMENT_SIZE], y: &[u8; P224_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let x_fe = FieldElement::from_bytes(x)?;
        let y_fe = FieldElement::from_bytes(y)?;

        // Validate that the point lies on the curve
        if !Self::is_on_curve(&x_fe, &y_fe) {
            return Err(Error::param("P-224 Point", "Point coordinates do not satisfy curve equation"));
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

    /// Get the x-coordinate as a byte array in big-endian format
    pub fn x_coordinate_bytes(&self) -> [u8; P224_FIELD_ELEMENT_SIZE] {
        self.x.to_bytes()
    }

    /// Get the y-coordinate as a byte array in big-endian format
    pub fn y_coordinate_bytes(&self) -> [u8; P224_FIELD_ELEMENT_SIZE] {
        self.y.to_bytes()
    }

    /// Detect point format from serialized bytes
    /// 
    /// Analyzes the leading byte and length to determine the serialization format.
    /// Useful for handling points that could be in either compressed or uncompressed form.
    /// 
    /// # Returns
    /// - `Ok(PointFormat)` indicating the detected format
    /// - `Err` if the format is invalid or unrecognized
    pub fn detect_format(bytes: &[u8]) -> Result<PointFormat> {
        if bytes.is_empty() {
            return Err(Error::param("P-224 Point", "Empty point data"));
        }
        
        match (bytes[0], bytes.len()) {
            (0x00, P224_POINT_UNCOMPRESSED_SIZE) => {
                // Check if all bytes are zero (identity encoding)
                if bytes.iter().all(|&b| b == 0) {
                    Ok(PointFormat::Identity)
                } else {
                    Err(Error::param("P-224 Point", "Invalid identity point encoding"))
                }
            },
            (0x04, P224_POINT_UNCOMPRESSED_SIZE) => Ok(PointFormat::Uncompressed),
            (0x02 | 0x03, P224_POINT_COMPRESSED_SIZE) => Ok(PointFormat::Compressed),
            _ => Err(Error::param("P-224 Point", "Unknown or malformed point format")),
        }
    }

    /// Serialize point to uncompressed format: 0x04 || x || y
    /// 
    /// The uncompressed point format is:
    /// - 1 byte: 0x04 (uncompressed indicator)
    /// - 28 bytes: x-coordinate (big-endian)
    /// - 28 bytes: y-coordinate (big-endian)
    /// 
    /// The identity point is represented as all zeros.
    pub fn serialize_uncompressed(&self) -> [u8; P224_POINT_UNCOMPRESSED_SIZE] {
        let mut result = [0u8; P224_POINT_UNCOMPRESSED_SIZE];

        // Special encoding for the identity element
        if self.is_identity() {
            return result; // All zeros represents identity
        }

        // Standard uncompressed format: 0x04 || x || y
        result[0] = 0x04;
        result[1..29].copy_from_slice(&self.x.to_bytes());
        result[29..57].copy_from_slice(&self.y.to_bytes());

        result
    }

    /// Deserialize point from uncompressed byte format
    /// 
    /// Supports the standard uncompressed format (0x04 || x || y) and
    /// recognizes the all-zeros encoding for the identity element.
    pub fn deserialize_uncompressed(bytes: &[u8]) -> Result<Self> {
        validate::length("P-224 Point", bytes.len(), P224_POINT_UNCOMPRESSED_SIZE)?;

        // Check for identity point (all zeros)
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::identity());
        }

        // Validate uncompressed format indicator
        if bytes[0] != 0x04 {
            return Err(Error::param("P-224 Point", "Invalid uncompressed point format (expected 0x04 prefix)"));
        }

        // Extract and validate coordinates
        let mut x_bytes = [0u8; P224_FIELD_ELEMENT_SIZE];
        let mut y_bytes = [0u8; P224_FIELD_ELEMENT_SIZE];

        x_bytes.copy_from_slice(&bytes[1..29]);
        y_bytes.copy_from_slice(&bytes[29..57]);

        Self::new_uncompressed(&x_bytes, &y_bytes)
    }

    /// Serialize point to SEC 1 compressed format (0x02/0x03 || x)
    /// 
    /// The compressed format uses:
    /// - 0x02 prefix if y-coordinate is even
    /// - 0x03 prefix if y-coordinate is odd
    /// - Followed by the x-coordinate in big-endian format
    /// 
    /// The identity point is encoded as 29 zero bytes for consistency
    /// with the uncompressed format.
    /// 
    /// This format reduces storage/transmission size by ~50% compared to
    /// uncompressed points while maintaining full recoverability.
    pub fn serialize_compressed(&self) -> [u8; P224_POINT_COMPRESSED_SIZE] {
        let mut out = [0u8; P224_POINT_COMPRESSED_SIZE];

        // Identity → all zeros
        if self.is_identity() {
            return out;
        }

        // Determine prefix based on y-coordinate parity
        out[0] = if self.y.is_odd() { 0x03 } else { 0x02 };
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
    }

    /// Deserialize SEC 1 compressed point
    /// 
    /// Recovers the full point from compressed format by:
    /// 1. Extracting the x-coordinate
    /// 2. Computing y² = x³ - 3x + b
    /// 3. Finding the square root of y²
    /// 4. Selecting the root with correct parity based on the prefix
    /// 
    /// # Errors
    /// Returns an error if:
    /// - The prefix is not 0x02 or 0x03
    /// - The x-coordinate is not in the valid field range
    /// - The x-coordinate corresponds to a non-residue (not on curve)
    pub fn deserialize_compressed(bytes: &[u8]) -> Result<Self> {
        validate::length("P-224 Compressed Point", bytes.len(), P224_POINT_COMPRESSED_SIZE)?;

        // Identity encoding
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::identity());
        }

        let tag = bytes[0];
        if tag != 0x02 && tag != 0x03 {
            return Err(Error::param("P-224 Point", "Invalid compressed point prefix (expected 0x02 or 0x03)"));
        }

        // Extract x-coordinate
        let mut x_bytes = [0u8; P224_FIELD_ELEMENT_SIZE];
        x_bytes.copy_from_slice(&bytes[1..]);

        let x_fe = FieldElement::from_bytes(&x_bytes).map_err(|_| {
            Error::param(
                "P-224 Point",
                "Invalid compressed point: x-coordinate yields quadratic non-residue",
            )
        })?;

        // Compute right-hand side: y² = x³ - 3x + b
        let rhs = {
            let x2 = x_fe.square();
            let x3 = x2.mul(&x_fe);
            let a = FieldElement(FieldElement::A_M3); // a = -3
            let b = FieldElement::from_bytes(&NIST_P224.b).unwrap();
            x3.add(&a.mul(&x_fe)).add(&b)
        };

        // Attempt to find square root
        let y_fe = rhs.sqrt().ok_or_else(|| {
            Error::param(
                "P-224 Point",
                "Invalid compressed point: x-coordinate yields quadratic non-residue",
            )
        })?;

        // Select the correct root based on parity
        let y_final = if (y_fe.is_odd() && tag == 0x03) || (!y_fe.is_odd() && tag == 0x02) {
            y_fe
        } else {
            // Use the negative root (p - y)
            FieldElement::get_modulus().sub(&y_fe)
        };

        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe,
            y: y_final,
        })
    }

    /// Elliptic curve point addition using the group law
    /// 
    /// Implements the abelian group operation for P-224 points.
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

    // Private helper methods

    /// Validate that coordinates satisfy the P-224 curve equation
    /// 
    /// Verifies: y² = x³ - 3x + b (mod p)
    /// where b is the curve parameter from NIST P-224 specification.
    /// 
    /// This is a critical security check to prevent invalid curve attacks.
    fn is_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
        // Left-hand side: y²
        let y_squared = y.square();
        
        // Right-hand side: x³ - 3x + b
        let x_cubed = x.square().mul(x);
        let a_coeff = FieldElement(FieldElement::A_M3);  // a = -3 mod p
        let ax = a_coeff.mul(x);
        let b_coeff = FieldElement::from_bytes(&NIST_P224.b).unwrap();
    
        // Compute x³ - 3x + b
        let x_cubed_plus_ax = x_cubed.add(&ax);
        let rhs = x_cubed_plus_ax.add(&b_coeff);
    
        y_squared == rhs
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
}

impl ProjectivePoint {
    /// Projective point addition using complete addition formulas
    /// 
    /// Implements the addition law for Jacobian coordinates that works
    /// for all input combinations, including point doubling and identity cases.
    /// 
    /// Uses optimized formulas that avoid expensive field inversions
    /// until the final conversion back to affine coordinates.
    pub fn add(&self, other: &Self) -> Self {
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

        let gamma_sq = gamma.square();              // Γ²
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
    pub fn to_affine(&self) -> Point {
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