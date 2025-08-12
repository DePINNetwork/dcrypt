//! ECDSA implementation for NIST P-192 curve
//!
//! This implementation follows FIPS 186-4: Digital Signature Standard (DSS)
//! and SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes
//! Using Discrete Logarithm Cryptography. SHA-256 is used as the hash function
//! as recommended for P-192.

use crate::ecdsa::common::SignatureComponents;
use dcrypt_algorithms::ec::p192 as ec; // Use P-192 algorithms
use dcrypt_algorithms::hash::sha2::Sha256; // Use Sha256
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_api::{error::Error as ApiError, Result as ApiResult, Signature as SignatureTrait};
use dcrypt_internal::constant_time::ct_eq;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// ECDSA signature scheme using NIST P-192 curve (secp192r1)
pub struct EcdsaP192;

/// P-192 public key in uncompressed format (0x04 || X || Y)
#[derive(Clone, Zeroize)]
pub struct EcdsaP192PublicKey(pub [u8; ec::P192_POINT_UNCOMPRESSED_SIZE]);

/// P-192 secret key
#[derive(Clone)]
pub struct EcdsaP192SecretKey {
    raw: ec::Scalar,
    bytes: [u8; ec::P192_SCALAR_SIZE],
}

impl Zeroize for EcdsaP192SecretKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        // self.raw is an ec::Scalar, which implements ZeroizeOnDrop.
    }
}

impl Drop for EcdsaP192SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// P-192 signature encoded in ASN.1 DER format
#[derive(Clone)]
pub struct EcdsaP192Signature(pub Vec<u8>);

// AsRef/AsMut implementations
impl AsRef<[u8]> for EcdsaP192PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdsaP192PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl AsRef<[u8]> for EcdsaP192SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
// REMOVED: AsMut<[u8]> for EcdsaP192SecretKey - Security: prevent direct mutation of secret key bytes
impl AsRef<[u8]> for EcdsaP192Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdsaP192Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl SignatureTrait for EcdsaP192 {
    type PublicKey = EcdsaP192PublicKey;
    type SecretKey = EcdsaP192SecretKey;
    type SignatureData = EcdsaP192Signature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDSA-P192"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) = ec::generate_keypair(rng).map_err(ApiError::from)?;

        let sk_bytes: [u8; ec::P192_SCALAR_SIZE] = sk_scalar.serialize();

        if sk_scalar.is_zero() {
            return Err(ApiError::InvalidParameter {
                context: "ECDSA-P192 keypair",
                #[cfg(feature = "std")]
                message: "Generated secret key is zero".to_string(),
            });
        }

        let secret_key = EcdsaP192SecretKey {
            raw: sk_scalar,
            bytes: sk_bytes,
        };
        let public_key = EcdsaP192PublicKey(pk_point.serialize_uncompressed());
        Ok((public_key, secret_key))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> ApiResult<Self::SignatureData> {
        let mut hasher = Sha256::new(); // Use SHA-256 for P-192
        hasher.update(message).map_err(ApiError::from)?;
        let hash_output = hasher.finalize().map_err(ApiError::from)?;

        // Truncate or reduce hash output to P-192 scalar size (24 bytes)
        let mut z_bytes_fixed_size = [0u8; ec::P192_SCALAR_SIZE];
        z_bytes_fixed_size.copy_from_slice(&hash_output.as_ref()[..ec::P192_SCALAR_SIZE]);
        let z = reduce_bytes_to_scalar_p192(&z_bytes_fixed_size)?;

        let d = secret_key.raw.clone();
        let mut rng = rand::thread_rng();

        loop {
            let k = deterministic_k_hedged_p192::<Sha256, _>(&d, &z, &mut rng); // Specify hash for k_hedged

            let kg = ec::scalar_mult_base_g(&k).map_err(ApiError::from)?;

            if kg.is_identity() {
                continue;
            }
            let r_bytes = kg.x_coordinate_bytes();

            let r = match reduce_bytes_to_scalar_p192(&r_bytes) {
                Ok(scalar) if !scalar.is_zero() => scalar,
                _ => continue,
            };

            let k_inv = k.inv_mod_n().map_err(ApiError::from)?;
            let rd = r.mul_mod_n(&d).map_err(ApiError::from)?;
            let z_plus_rd = z.add_mod_n(&rd).map_err(ApiError::from)?;
            let s = k_inv.mul_mod_n(&z_plus_rd).map_err(ApiError::from)?;

            if s.is_zero() {
                continue;
            }

            let sig_comps = SignatureComponents {
                r: r.serialize().to_vec(),
                s: s.serialize().to_vec(),
            };
            return Ok(EcdsaP192Signature(sig_comps.to_der()));
        }
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> ApiResult<()> {
        let sig_comps = SignatureComponents::from_der(&signature.0)?;

        if sig_comps.r.len() > ec::P192_SCALAR_SIZE || sig_comps.s.len() > ec::P192_SCALAR_SIZE {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P192 verify",
                #[cfg(feature = "std")]
                message: "Invalid signature component size".to_string(),
            });
        }

        let mut r_bytes = [0u8; ec::P192_SCALAR_SIZE];
        let mut s_bytes = [0u8; ec::P192_SCALAR_SIZE];
        let r_offset = ec::P192_SCALAR_SIZE.saturating_sub(sig_comps.r.len());
        let s_offset = ec::P192_SCALAR_SIZE.saturating_sub(sig_comps.s.len());
        r_bytes[r_offset..].copy_from_slice(&sig_comps.r);
        s_bytes[s_offset..].copy_from_slice(&sig_comps.s);

        let r = ec::Scalar::new(r_bytes).map_err(|_| ApiError::InvalidSignature {
            context: "ECDSA-P192 verify",
            #[cfg(feature = "std")]
            message: "Invalid r component".to_string(),
        })?;
        let s = ec::Scalar::new(s_bytes).map_err(|_| ApiError::InvalidSignature {
            context: "ECDSA-P192 verify",
            #[cfg(feature = "std")]
            message: "Invalid s component".to_string(),
        })?;

        let mut hasher = Sha256::new(); // Use SHA-256
        hasher.update(message).map_err(ApiError::from)?;
        let hash_output = hasher.finalize().map_err(ApiError::from)?;

        let mut z_bytes_fixed_size = [0u8; ec::P192_SCALAR_SIZE];
        z_bytes_fixed_size.copy_from_slice(&hash_output.as_ref()[..ec::P192_SCALAR_SIZE]); // Truncate SHA-256 output
        let z = reduce_bytes_to_scalar_p192(&z_bytes_fixed_size)?;

        let s_inv = s.inv_mod_n().map_err(ApiError::from)?;
        let u1 = z.mul_mod_n(&s_inv).map_err(ApiError::from)?;
        let u2 = r.mul_mod_n(&s_inv).map_err(ApiError::from)?;

        let q_point = ec::Point::deserialize_uncompressed(&public_key.0).map_err(ApiError::from)?;

        if q_point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "ECDSA-P192 verify",
                #[cfg(feature = "std")]
                message: "Public key is the point at infinity".to_string(),
            });
        }

        let u1g = ec::scalar_mult_base_g(&u1).map_err(ApiError::from)?;
        let u2q = ec::scalar_mult(&u2, &q_point).map_err(ApiError::from)?;

        let point = u1g.add(&u2q);

        if point.is_identity() {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P192 verify",
                #[cfg(feature = "std")]
                message: "Verification point is identity".to_string(),
            });
        }

        let x1_bytes = point.x_coordinate_bytes();
        let v = reduce_bytes_to_scalar_p192(&x1_bytes)?;

        if !ct_eq(r.serialize(), v.serialize()) {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P192 verify",
                #[cfg(feature = "std")]
                message: "Signature verification failed (r != v)".to_string(),
            });
        }
        Ok(())
    }
}

// Adapt deterministic_k_hedged for P-192 using a specified HashFunction (e.g., Sha256)
fn deterministic_k_hedged_p192<H: HashFunction + Clone, R: RngCore + CryptoRng>(
    d: &ec::Scalar,
    z: &ec::Scalar,
    rng: &mut R,
) -> ec::Scalar {
    use zeroize::Zeroize;
    let hash_len = H::output_size(); // e.g., 32 for Sha256
    let hmac_block_len = H::block_size();

    let mut rbuf = [0u8; ec::P192_SCALAR_SIZE]; // 24 bytes for P-192
    rng.fill_bytes(&mut rbuf);

    let mut v_hmac_block = vec![0x01u8; hmac_block_len];
    let mut k_hmac_block = vec![0x00u8; hmac_block_len];

    // Step C
    {
        let mut mac = Hmac::<H>::new(&k_hmac_block).unwrap();
        mac.update(&v_hmac_block).unwrap();
        mac.update(&[0x00]).unwrap();
        mac.update(&d.serialize()).unwrap();
        mac.update(&z.serialize()).unwrap();
        mac.update(&rbuf).unwrap();
        let mac_res = mac.finalize().unwrap();
        k_hmac_block[..hash_len].copy_from_slice(&mac_res);
        k_hmac_block[hash_len..].fill(0);
    }
    // Step D
    let v_new_res = Hmac::<H>::mac(&k_hmac_block, &v_hmac_block).unwrap();
    v_hmac_block[..hash_len].copy_from_slice(&v_new_res);
    v_hmac_block[hash_len..].fill(0);
    // Step E
    {
        let mut mac = Hmac::<H>::new(&k_hmac_block).unwrap();
        mac.update(&v_hmac_block).unwrap();
        mac.update(&[0x01]).unwrap();
        mac.update(&d.serialize()).unwrap();
        mac.update(&z.serialize()).unwrap();
        mac.update(&rbuf).unwrap();
        let mac_res = mac.finalize().unwrap();
        k_hmac_block[..hash_len].copy_from_slice(&mac_res);
        k_hmac_block[hash_len..].fill(0);
    }
    // Step F
    let v_new_res = Hmac::<H>::mac(&k_hmac_block, &v_hmac_block).unwrap();
    v_hmac_block[..hash_len].copy_from_slice(&v_new_res);
    v_hmac_block[hash_len..].fill(0);

    // Step G/H
    loop {
        let v_new_res = Hmac::<H>::mac(&k_hmac_block, &v_hmac_block).unwrap();
        v_hmac_block[..hash_len].copy_from_slice(&v_new_res);
        v_hmac_block[hash_len..].fill(0);

        let mut candidate_scalar_bytes = [0u8; ec::P192_SCALAR_SIZE];
        candidate_scalar_bytes.copy_from_slice(&v_hmac_block[..ec::P192_SCALAR_SIZE]);

        if let Ok(candidate) = ec::Scalar::new(candidate_scalar_bytes) {
            rbuf.zeroize();
            return candidate;
        }

        let mut mac = Hmac::<H>::new(&k_hmac_block).unwrap();
        mac.update(&v_hmac_block).unwrap();
        mac.update(&[0x00]).unwrap();
        let mac_res = mac.finalize().unwrap();
        k_hmac_block[..hash_len].copy_from_slice(&mac_res);
        k_hmac_block[hash_len..].fill(0);

        let v_new_res = Hmac::<H>::mac(&k_hmac_block, &v_hmac_block).unwrap();
        v_hmac_block[..hash_len].copy_from_slice(&v_new_res);
        v_hmac_block[hash_len..].fill(0);
    }
}

fn reduce_bytes_to_scalar_p192(bytes: &[u8; ec::P192_SCALAR_SIZE]) -> ApiResult<ec::Scalar> {
    ec::Scalar::new(*bytes).map_err(|algo_err| match algo_err {
        dcrypt_algorithms::error::Error::Parameter {
            ref name,
            ref reason,
        } if name.as_ref() == "P-192 Scalar"
            && reason.as_ref().contains("Scalar cannot be zero") =>
        {
            ApiError::InvalidSignature {
                context: "ECDSA-P192 scalar reduction",
                #[cfg(feature = "std")]
                message: "Computed scalar component is zero or invalid".to_string(),
            }
        }
        _ => ApiError::from(algo_err),
    })
}

#[cfg(test)]
mod tests;