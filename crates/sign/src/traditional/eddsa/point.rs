//! Edwards curve point operations for Ed25519
//!
//! This module implements point arithmetic on the twisted Edwards curve
//! -x² + y² = 1 + d·x²·y² where d = -121665/121666

use super::constants::{BASE_X, BASE_Y, D};
use super::field::{FieldElement, sqrt};
use super::scalar::Scalar;

/// Point on the twisted Edwards curve
#[derive(Clone)]
pub struct EdwardsPoint {
    // Extended coordinates (X:Y:Z:T) where x=X/Z, y=Y/Z, xy=T/Z
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

/// Compressed point representation (32 bytes)
#[derive(Clone, Copy)]
pub struct CompressedPoint {
    pub(crate) bytes: [u8; 32],
}

impl EdwardsPoint {
    /// Identity element (neutral element for addition)
    pub fn identity() -> Self {
        EdwardsPoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }
    
    /// Base point generator
    pub fn base_point() -> Self {
        let x = FieldElement::from_bytes(&BASE_X);
        let y = FieldElement::from_bytes(&BASE_Y);
        let t = x.mul(&y);
        
        EdwardsPoint {
            x,
            y,
            z: FieldElement::one(),
            t,
        }
    }
    
    /// Add two points
    pub fn add(&self, other: &EdwardsPoint) -> EdwardsPoint {
        let x1 = &self.x;
        let y1 = &self.y;
        let z1 = &self.z;
        let t1 = &self.t;
        
        let x2 = &other.x;
        let y2 = &other.y;
        let z2 = &other.z;
        let t2 = &other.t;
        
        let d2 = d_times_2();
        
        let a = y1.sub(x1).mul(&y2.sub(x2));
        let b = y1.add(x1).mul(&y2.add(x2));
        let c = t1.mul(t2).mul(&d2);
        let d = z1.double().mul(z2);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        
        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }
    
    /// Double a point
    pub fn double(&self) -> EdwardsPoint {
        // A Twisted-Edwards "add" formula is *complete*, so we can obtain
        // 2·P simply by adding P to itself. This leverages the thoroughly
        // unit-tested `add()` routine and avoids subtle sign/constant errors.
        //
        //   P2 = P + P
        self.add(self)
    }
    
    /// Scalar multiplication using double-and-add
    pub fn scalar_mult(&self, scalar: &Scalar) -> EdwardsPoint {
        let mut result = EdwardsPoint::identity();
        let mut temp = self.clone();
        
        for i in 0..256 {
            let bit = (scalar.bytes[i / 8] >> (i % 8)) & 1;
            if bit == 1 {
                result = result.add(&temp);
            }
            temp = temp.double();
        }
        
        result
    }
    
    /// Compress point to 32 bytes
    pub fn compress(&self) -> CompressedPoint {
        let recip = self.z.invert();
        let x = self.x.mul(&recip);
        let y = self.y.mul(&recip);
        
        let mut bytes = y.to_bytes();
        let x_bytes = x.to_bytes();
        
        // Clear bit 255 first (RFC 8032 § 5.1.2 step 2)
        bytes[31] &= 0x7F;
        // Then set sign bit (bit 255) based on x coordinate parity
        bytes[31] |= (x_bytes[0] & 1) << 7;
        
        CompressedPoint { bytes }
    }
    
    /// Check if this point is on the curve (for debugging)
    #[cfg(test)]
    pub fn is_on_curve(&self) -> bool {
        use dcrypt_internal::constant_time::ct_eq;
        
        // Check: -X² + Y² = Z² + d·X²·Y²·Z⁻²
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let zz_inv = zz.invert();
        
        let lhs = yy.sub(&xx);  // -X² + Y²
        let rhs = zz.add(&d().mul(&xx).mul(&yy).mul(&zz_inv));  // Z² + d·X²·Y²·Z⁻²
        
        ct_eq(lhs.to_bytes(), rhs.to_bytes())
    }
}

impl CompressedPoint {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        CompressedPoint { bytes: *bytes }
    }
    
    /// Get bytes
    pub fn to_bytes(self) -> [u8; 32] {
        self.bytes
    }
    
    /// Decompress to point
    pub fn decompress(&self) -> Option<EdwardsPoint> {
        let mut y_bytes = self.bytes;
        let sign = (y_bytes[31] >> 7) & 1;
        y_bytes[31] &= 0x7f;
        
        let y = FieldElement::from_bytes(&y_bytes);
        
        let x = recover_x(&y, sign == 1)?;
        
        let t = x.mul(&y);
        
        Some(EdwardsPoint {
            x,
            y,
            z: FieldElement::one(),
            t,
        })
    }
}

// Helper functions

/// d = -121665/121666
fn d() -> FieldElement {
    FieldElement::from_bytes(&D)
}

/// 2*d
fn d_times_2() -> FieldElement {
    d().double()
}

/// Recover x coordinate from y and sign bit
fn recover_x(y: &FieldElement, sign: bool) -> Option<FieldElement> {
    let yy = y.square();
    let u = yy.sub(&FieldElement::one());
    let v = d().mul(&yy).add(&FieldElement::one());
    let v_inv = v.invert();
    
    let x2 = u.mul(&v_inv);
    
    let mut x = sqrt(&x2)?;
    
    // Ensure correct sign
    let x_bytes = x.to_bytes();
    
    if ((x_bytes[0] & 1) == 1) != sign {
        x = x.neg();
    }
    
    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_point_operations() {
        let g = EdwardsPoint::base_point();
        let g2 = g.double();
        let g3 = g.add(&g2);
        
        // Check that operations produce different points
        let g_compressed = g.compress().to_bytes();
        let g2_compressed = g2.compress().to_bytes();
        let g3_compressed = g3.compress().to_bytes();
        
        assert_ne!(g_compressed, g2_compressed);
        assert_ne!(g_compressed, g3_compressed);
        assert_ne!(g2_compressed, g3_compressed);
    }
    
    #[test]
    fn test_basic_scalar_mult_stays_on_curve() {
        let g = EdwardsPoint::base_point();
        assert!(g.is_on_curve(), "Base point not on curve!");
        
        let s1 = Scalar::from_bytes(&[1; 32]);
        let p1 = g.scalar_mult(&s1);
        assert!(p1.is_on_curve(), "Point after scalar mult by 1 not on curve!");
        
        let s2 = Scalar::from_bytes(&[2; 32]);
        let p2 = g.scalar_mult(&s2);
        assert!(p2.is_on_curve(), "Point after scalar mult by 2 not on curve!");
        
        // Test that they can be compressed and decompressed
        let c1 = p1.compress();
        assert!(c1.decompress().is_some(), "Failed to decompress point after scalar mult by 1");
        
        let c2 = p2.compress();
        assert!(c2.decompress().is_some(), "Failed to decompress point after scalar mult by 2");
    }
}