// File: crates/sign/src/pq/dilithium/mod.rs
//! Dilithium Digital Signature Algorithm (as per FIPS 203)
//!
//! This module provides high-level implementations for Dilithium2, Dilithium3, and Dilithium5,
//! which are lattice-based digital signature schemes standardized by NIST.
//!
//! The core cryptographic logic relies on polynomial arithmetic over rings, specific sampling
//! distributions (Centered Binomial Distribution, uniform bounded for `y`, sparse ternary for `c`),
//! and cryptographic hash functions (SHA3, SHAKE) provided by the `dcrypt-algorithms` crate.
//! The security of Dilithium is based on the hardness of the Module Learning With Errors (MLWE)
//! and Module Short Integer Solution (MSIS) problems over polynomial rings.
//!
//! The signing process employs the Fiat-Shamir with Aborts paradigm to achieve security
//! against chosen message attacks.
//!
//! This module defines the public API for Dilithium, conforming to the `dcrypt-api::Signature` trait.
//! Detailed implementations of internal operations are found in submodules:
//! - `polyvec.rs`: Defines `PolyVecL`, `PolyVecK` and Dilithium-specific polynomial vector operations.
//! - `arithmetic.rs`: Implements crucial arithmetic functions like `Power2Round`, `Decompose`,
//!   `MakeHint`, `UseHint`, and coefficient norm checking.
//! - `sampling.rs`: Implements Dilithium-specific sampling procedures for secret polynomials,
//!   the masking vector `y`, and the challenge polynomial `c`.
//! - `encoding.rs`: Handles the precise serialization and deserialization formats for public keys,
//!   secret keys, and signatures as specified by FIPS 203.
//! - `sign.rs`: Contains the core `keypair_internal`, `sign_internal`, and `verify_internal` logic.

use api::{Signature as SignatureTrait, Result as ApiResult};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{CryptoRng, RngCore};
use core::marker::PhantomData;

// Internal modules for Dilithium logic
mod polyvec;       
mod arithmetic;    
mod sampling;      
mod encoding;      
mod sign;          

// Re-export from params crate for easy access to DilithiumNParams structs.
// These structs from `dcrypt-params` hold the specific numerical parameters (K, L, eta, gamma1, etc.)
// that define each Dilithium security level.
use params::pqc::dilithium::{Dilithium2Params, Dilithium3Params, Dilithium5Params, DilithiumSchemeParams};

// --- Public Key, Secret Key, Signature Data Wrapper Structs ---
// These structs wrap byte vectors (`Vec<u8>`) that store the serialized representations
// of the cryptographic objects. They provide a type-safe interface at the API boundary.

/// Dilithium Public Key.
///
/// Stores the packed representation of `(rho, t1)`.
/// - `rho`: A 32-byte seed used to deterministically generate the matrix A.
/// - `t1`: A vector of K polynomials, where each coefficient is the high-order bits
///   of `t_i = (A*s1)_i + (s2)_i`. Packed according to `P::D_PARAM` bits.
#[derive(Clone, Debug, Zeroize)]
pub struct DilithiumPublicKey(pub(crate) Vec<u8>);

/// Dilithium Secret Key.
///
/// Stores the packed representation of `(rho, K, tr, s1, s2, t0)`.
/// - `rho`: Seed for matrix A (same as in public key).
/// - `K`: A 32-byte seed used for sampling the masking vector `y` and as part of the
///   PRF input for generating the challenge `c`.
/// - `tr`: A 32-byte hash of the packed public key, used for domain separation in challenge generation.
/// - `s1`, `s2`: Secret polynomial vectors with small coefficients (norm bounded by `eta`).
///   Packed according to `P::ETA_S1S2` bits.
/// - `t0`: A vector of K polynomials representing the low-order bits of `t = A*s1 + s2`.
///   Coefficients are in `(-2^(d-1), 2^(d-1)]` and packed accordingly.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSecretKey(pub(crate) Vec<u8>);

/// Dilithium Signature Data.
///
/// Stores the packed representation of `(c_tilde, z, h)`.
/// - `c_tilde`: A short (32-byte) seed from which the challenge polynomial `c` (with `tau` non-zero
///   coefficients) is derived.
/// - `z`: A vector of L polynomials, `z = y + c*s1`. Its coefficients must be within
///   `[-gamma1 + beta, gamma1 - beta]`. Packed based on this range.
/// - `h`: A hint vector (PolyVecK of 0s/1s) indicating which coefficients of `w1_prime - c*t0`
///   required correction during verification using `UseHint`. Packed efficiently.
#[derive(Clone, Debug)]
pub struct DilithiumSignatureData(pub(crate) Vec<u8>);

// AsRef/AsMut implementations allow access to the raw byte data.
impl AsRef<[u8]> for DilithiumPublicKey { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for DilithiumPublicKey { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }
impl AsRef<[u8]> for DilithiumSecretKey { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for DilithiumSecretKey { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }
impl AsRef<[u8]> for DilithiumSignatureData { fn as_ref(&self) -> &[u8] { &self.0 } }
impl AsMut<[u8]> for DilithiumSignatureData { fn as_mut(&mut self) -> &mut [u8] { &mut self.0 } }


/// Generic Dilithium signature structure parameterized by `P: DilithiumSchemeParams`.
/// This allows a single core implementation (`sign.rs`) to be instantiated for
/// different Dilithium security levels (Dilithium2, Dilithium3, Dilithium5)
/// by simply changing the type parameter `P`.
pub struct Dilithium<P: DilithiumSchemeParams + 'static> {
    _params: PhantomData<P>,
}

// --- Implement api::Signature for Dilithium<P> ---
impl<P: DilithiumSchemeParams + Send + Sync + 'static> SignatureTrait for Dilithium<P> {
    type PublicKey = DilithiumPublicKey;
    type SecretKey = DilithiumSecretKey;
    type SignatureData = DilithiumSignatureData;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str { P::NAME }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (pk_bytes, sk_bytes) = sign::keypair_internal::<P, R>(rng)
            .map_err(api::Error::from)?;
        Ok((DilithiumPublicKey(pk_bytes), DilithiumSecretKey(sk_bytes)))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey { keypair.0.clone() }
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey { keypair.1.clone() }

    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> ApiResult<Self::SignatureData> {
        // Dilithium signing, as per FIPS 203, is deterministic given the secret key and message.
        // The internal randomness for the masking vector `y` and the challenge `c` (via its seed)
        // are derived from parts of the secret key (`K`) and a counter (`kappa`).
        // An external RNG is not directly consumed by the core signing loop after `K` is fixed.
        // However, some library designs might use an RNG for the initial seed `K` itself if it's
        // not part of a deterministic derivation from a master seed.
        // For this API, we'll use a thread_rng for any potential non-spec randomization points
        // or if a future variant required it, but standard Dilithium does not.
        let mut rng = rand::rngs::OsRng;
        let sig_bytes = sign::sign_internal::<P, _>(message, &secret_key.0, &mut rng)
            .map_err(api::Error::from)?;
        Ok(DilithiumSignatureData(sig_bytes))
    }

    fn verify(message: &[u8], signature: &Self::SignatureData, public_key: &Self::PublicKey) -> ApiResult<()> {
        sign::verify_internal::<P>(message, &signature.0, &public_key.0)
            .map_err(api::Error::from)
    }
}

// Concrete types for different Dilithium levels, re-exporting the generic Dilithium struct
// instantiated with specific parameters from the `params` crate.
pub type Dilithium2 = Dilithium<Dilithium2Params>;
pub type Dilithium3 = Dilithium<Dilithium3Params>;
pub type Dilithium5 = Dilithium<Dilithium5Params>;

#[cfg(test)]
mod tests;