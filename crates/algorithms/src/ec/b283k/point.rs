//! sect283k1 elliptic curve point operations

use crate::ec::b283k::{
    constants::{
        B283K_FIELD_ELEMENT_SIZE, B283K_POINT_COMPRESSED_SIZE,
    },
    field::FieldElement,
    scalar::Scalar,
};
use crate::error::{validate, Error, Result};
use subtle::Choice;

/// Format of a serialized elliptic curve point
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointFormat {
    /// The point at infinity (identity element)
    Identity,
    /// Uncompressed format: 0x04 || x || y
    Uncompressed,
    /// Compressed format: 0x02/0x03 || x
    Compressed,
}

/// A point on the sect283k1 elliptic curve
#[derive(Clone, Debug)]
pub struct Point {
    pub(crate) is_identity: Choice,
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        let self_is_identity: bool = self.is_identity.into();
        let other_is_identity: bool = other.is_identity.into();

        if self_is_identity || other_is_identity {
            return self_is_identity == other_is_identity;
        }

        self.x == other.x && self.y == other.y
    }
}

impl Eq for Point {}

impl Point {
    /// Create a new point from uncompressed coordinates.
    ///
    /// Returns an error if the coordinates don't satisfy the curve equation y² + xy = x³ + 1.
    pub fn new_uncompressed(
        x: &[u8; B283K_FIELD_ELEMENT_SIZE],
        y: &[u8; B283K_FIELD_ELEMENT_SIZE],
    ) -> Result<Self> {
        let x_fe = FieldElement::from_bytes(x)?;
        let y_fe = FieldElement::from_bytes(y)?;
        if !Self::is_on_curve(&x_fe, &y_fe) {
            return Err(Error::param(
                "B283k Point",
                "Point coordinates do not satisfy curve equation",
            ));
        }
        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe,
            y: y_fe,
        })
    }

    /// Create the identity point (point at infinity).
    pub fn identity() -> Self {
        Point {
            is_identity: Choice::from(1),
            x: FieldElement::zero(),
            y: FieldElement::zero(),
        }
    }

    /// Check if this point is the identity element.
    pub fn is_identity(&self) -> bool {
        self.is_identity.into()
    }

    /// Get the x-coordinate of this point as bytes.
    pub fn x_coordinate_bytes(&self) -> [u8; B283K_FIELD_ELEMENT_SIZE] {
        self.x.to_bytes()
    }

    /// Get the y-coordinate of this point as bytes.
    pub fn y_coordinate_bytes(&self) -> [u8; B283K_FIELD_ELEMENT_SIZE] {
        self.y.to_bytes()
    }

    /// Serialize this point in compressed format.
    ///
    /// The compressed format uses the trace to disambiguate the y-coordinate.
    pub fn serialize_compressed(&self) -> [u8; B283K_POINT_COMPRESSED_SIZE] {
        let mut out = [0u8; B283K_POINT_COMPRESSED_SIZE];
        if self.is_identity() {
            return out;
        }

        let y_tilde = self.x.invert().unwrap().mul(&self.y).trace();
        out[0] = if y_tilde == 1 { 0x03 } else { 0x02 };
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
    }

    /// Deserialize a point from compressed format.
    ///
    /// Recovers the y-coordinate from the x-coordinate and the compression flag.
    /// Returns an error if the bytes don't represent a valid point.
    pub fn deserialize_compressed(bytes: &[u8]) -> Result<Self> {
        validate::length(
            "B283k Compressed Point",
            bytes.len(),
            B283K_POINT_COMPRESSED_SIZE,
        )?;
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::identity());
        }
        let tag = bytes[0];
        if tag != 0x02 && tag != 0x03 {
            return Err(Error::param(
                "B283k Point",
                "Invalid compressed point prefix",
            ));
        }
        let mut x_bytes = [0u8; B283K_FIELD_ELEMENT_SIZE];
        x_bytes.copy_from_slice(&bytes[1..]);
        let x = FieldElement::from_bytes(&x_bytes)?;
        if x.is_zero() {
            return Ok(Point {
                is_identity: Choice::from(0),
                x,
                y: FieldElement::one().sqrt(),
            });
        }

        // y^2 + xy = x^3 + 1 => y^2 + xy + (x^3 + 1) = 0
        // Let z = y/x. z^2*x^2 + x*z*x + x^3 + 1 = 0 => z^2*x^2 + x^2*z + x^3 + 1 = 0
        // z^2 + z = x + 1/x^2
        let rhs = x.add(&x.square().invert().unwrap());

        // Step 1: Check existence of a solution
        if rhs.trace() != 0 {
            return Err(Error::param("B283k Point", "Cannot decompress point"));
        }

        // Step 2: Solve z^2 + z = rhs using half-trace
        let mut z = Self::half_trace(&rhs);

        // Step 3: Choose the root whose LSB matches ~y_P
        if z.trace() != (tag as u64 - 2) {
            z = z.add(&FieldElement::one());
        }

        let y = x.mul(&z);
        Ok(Point {
            is_identity: Choice::from(0),
            x,
            y,
        })
    }

    /// Return the half-trace of `a` in GF(2^283).
    ///
    /// For odd m, the half-trace Htr(a) = sum_{i=0}^{(m-1)/2} a^{2^{2i}}
    /// satisfies Htr(a)^2 + Htr(a) = a when Tr(a) = 0.
    fn half_trace(a: &FieldElement) -> FieldElement {
        // m = 283 → (m-1)/2 = 141
        let mut ht = *a; // a^{2^{0}}
        let mut t = *a;
        for _ in 0..141 {
            t = t.square(); // a^{2^{2k+1}}
            t = t.square(); // a^{2^{2k+2}} = a^{2^{2(k+1)}}
            ht = ht.add(&t); // accumulate a^{2^{2(k+1)}}
        }
        ht
    }

    /// Add two points using the group law for binary elliptic curves.
    pub fn add(&self, other: &Self) -> Self {
        if self.is_identity() {
            return other.clone();
        }
        if other.is_identity() {
            return self.clone();
        }

        if self.x == other.x {
            if self.y == other.y {
                return self.double();
            } else {
                return Self::identity();
            }
        }

        let lambda = (self.y.add(&other.y)).mul(&(self.x.add(&other.x)).invert().unwrap());
        let x3 = lambda.square().add(&lambda).add(&self.x).add(&other.x);
        let y3 = lambda.mul(&(self.x.add(&x3))).add(&x3).add(&self.y);
        Point {
            is_identity: Choice::from(0),
            x: x3,
            y: y3,
        }
    }

    /// Double a point (add it to itself).
    pub fn double(&self) -> Self {
        if self.is_identity() || self.x.is_zero() {
            return Self::identity();
        }

        let lambda = self.x.add(&self.y.mul(&self.x.invert().unwrap()));
        let x2 = lambda.square().add(&lambda);
        let y2 = self.x.square().add(&lambda.mul(&x2)).add(&x2);
        Point {
            is_identity: Choice::from(0),
            x: x2,
            y: y2,
        }
    }

    /// Scalar multiplication: compute scalar * self.
    ///
    /// Uses constant-time double-and-add algorithm.
    pub fn mul(&self, scalar: &Scalar) -> Result<Self> {
        if scalar.is_zero() {
            return Ok(Self::identity());
        }
        let scalar_bytes = scalar.as_secret_buffer().as_ref();
        let mut res = Self::identity();
        let mut temp = self.clone();

        for byte in scalar_bytes.iter().rev() {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    res = res.add(&temp);
                }
                temp = temp.double();
            }
        }
        Ok(res)
    }

    fn is_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
        // y^2 + xy = x^3 + 1
        let y_sq = y.square();
        let xy = x.mul(y);
        let lhs = y_sq.add(&xy);

        let x_cubed = x.square().mul(x);
        let rhs = x_cubed.add(&FieldElement::one());

        lhs == rhs
    }
}