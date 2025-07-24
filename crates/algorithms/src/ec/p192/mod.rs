//! NIST P-192 Elliptic Curve Primitives
//!
//! This module implements NIST P-192 elliptic curve operations in constant time.
//! Curve equation: y² = x³ - 3x + b over 𝔽ₚ, where
//! - p = 2¹⁹² − 2⁶⁴ − 1,
//! - Curve order n = 0xFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF.  (NIST P-192 order).
//!
//! Implements:
//! - Mersenne reduction for 𝔽ₚ (2¹⁹² ≡ 2⁶⁴ + 1),
//! - Jacobian projective coordinates for point operations,
//! - Constant‐time scalar multiplication, addition, etc.

mod constants;
mod field;
mod point;
mod scalar;

pub use constants::{
    P192_SCALAR_SIZE,
    P192_FIELD_ELEMENT_SIZE,
    P192_POINT_UNCOMPRESSED_SIZE,
    P192_POINT_COMPRESSED_SIZE,
    P192_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
};
pub use field::FieldElement;
pub use point::{Point, PointFormat};
pub use scalar::Scalar;

use crate::error::{Error, Result};
use crate::kdf::hkdf::Hkdf;
use crate::hash::sha2::Sha256;
use crate::kdf::KeyDerivationFunction as KdfTrait;
use rand::{CryptoRng, RngCore};
use dcrypt_params::traditional::ecdsa::NIST_P192;

/// Get the standard base point G of the P-192 curve
pub fn base_point_g() -> Point {
    Point::new_uncompressed(&NIST_P192.g_x, &NIST_P192.g_y)
        .expect("Standard base point must be valid")
}

/// Scalar multiplication with the base point: scalar * G
pub fn scalar_mult_base_g(scalar: &Scalar) -> Result<Point> {
    let g = base_point_g();
    g.mul(scalar)
}

/// Generate a cryptographically secure ECDH keypair
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(Scalar, Point)> {
    let mut scalar_bytes = [0u8; P192_SCALAR_SIZE];
    loop {
        rng.fill_bytes(&mut scalar_bytes);
        match Scalar::new(scalar_bytes) {
            Ok(privk) => {
                let pubk = scalar_mult_base_g(&privk)?;
                return Ok((privk, pubk));
            }
            Err(_) => continue,
        }
    }
}

/// General scalar multiplication: compute scalar * arbitrary point
pub fn scalar_mult(scalar: &Scalar, point: &Point) -> Result<Point> {
    if point.is_identity() {
        Ok(Point::identity())
    } else {
        point.mul(scalar)
    }
}

/// Key derivation for ECDH shared secret using HKDF-SHA256
pub fn kdf_hkdf_sha256_for_ecdh_kem(
    ikm: &[u8],
    info: Option<&[u8]>,
) -> Result<[u8; P192_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE]> {
    let hkdf = <Hkdf<Sha256, 16> as KdfTrait>::new();
    let derived = hkdf.derive_key(ikm, None, info, P192_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE)?;
    let mut out = [0u8; P192_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE];
    if derived.len() == P192_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE {
        out.copy_from_slice(&derived);
        Ok(out)
    } else {
        Err(Error::Length {
            context: "KDF output for ECDH P-192",
            expected: P192_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
            actual: derived.len(),
        })
    }
}

#[cfg(test)]
mod tests;