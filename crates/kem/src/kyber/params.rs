// kem/src/kyber/params.rs

//! Kyber parameter definitions.
#![cfg_attr(not(feature = "std"), no_std)]

use algorithms::poly::params::{Modulus, NttModulus, PostInvNtt};
use params::pqc::kyber as global_params; // Using an alias for clarity

/// Common Kyber polynomial degree.
pub const KYBER_N: usize = global_params::KYBER_N;
/// Common Kyber coefficient modulus.
pub const KYBER_Q: u32 = global_params::KYBER_Q as u32;
/// Shared secret size for all Kyber variants.
pub const KYBER_SS_BYTES: usize = 32;

/// Trait defining parameters for a specific Kyber variant.
pub trait KyberParams: Send + Sync + 'static {
    /// Security parameter k (dimension of vectors/matrices).
    const K: usize;
    /// Noise parameter eta1 for secret s, e.
    const ETA1: u8;
    /// Noise parameter eta2 for error e1, e2.
    const ETA2: u8;
    /// Compression bits for vector u (part of ciphertext).
    const DU: usize;
    /// Compression bits for polynomial v (part of ciphertext).
    const DV: usize;

    /// Algorithm name string.
    const NAME: &'static str;
    /// Size of the public key in bytes.
    const PUBLIC_KEY_BYTES: usize;
    /// Size of the secret key in bytes.
    const SECRET_KEY_BYTES: usize;
    /// Size of the ciphertext in bytes.
    const CIPHERTEXT_BYTES: usize;
}

/// Struct implementing `Modulus` for Kyber polynomials.
/// Used as a generic parameter for `algorithms::poly::Polynomial`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KyberPolyModParams;

impl Modulus for KyberPolyModParams {
    const Q: u32 = KYBER_Q;
    const N: usize = KYBER_N;
}

// Implement NttModulus trait for KyberPolyModParams
impl NttModulus for KyberPolyModParams {
    const ZETA: u32 = 17;  // primitive 512-th root of unity mod 3329
    const ZETAS: &'static [u32] = &[];  // Not used with on-the-fly generation
    const N_INV: u32 = 2385;  // 256^-1 · R mod 3329
    const MONT_R: u32 = 1353;  // 2^32 mod 3329
    const NEG_QINV: u32 = 0x94570CFF;  // -Q^-1 mod 2^32
    
    // Kyber doesn't use twisting, so these are empty
    const PSIS: &'static [u32] = &[];
    const INV_PSIS: &'static [u32] = &[];

    // Kyber wants standard-domain coefficients after InvNTT
    const POST_INVNTT_MODE: PostInvNtt = PostInvNtt::Standard;
}

// Concrete parameter implementations for Kyber variants.

pub struct Kyber512ParamsImpl;
impl KyberParams for Kyber512ParamsImpl {
    const K: usize = global_params::KYBER512.k;
    const ETA1: u8 = global_params::KYBER512.eta1;
    const ETA2: u8 = global_params::KYBER512.eta2;
    const DU: usize = global_params::KYBER512.du;
    const DV: usize = global_params::KYBER512.dv;
    const NAME: &'static str = "Kyber-512";
    const PUBLIC_KEY_BYTES: usize = global_params::KYBER512.public_key_size;
    const SECRET_KEY_BYTES: usize = global_params::KYBER512.secret_key_size;
    const CIPHERTEXT_BYTES: usize = global_params::KYBER512.ciphertext_size;
}

pub struct Kyber768ParamsImpl;
impl KyberParams for Kyber768ParamsImpl {
    const K: usize = global_params::KYBER768.k;
    const ETA1: u8 = global_params::KYBER768.eta1;
    const ETA2: u8 = global_params::KYBER768.eta2;
    const DU: usize = global_params::KYBER768.du;
    const DV: usize = global_params::KYBER768.dv;
    const NAME: &'static str = "Kyber-768";
    const PUBLIC_KEY_BYTES: usize = global_params::KYBER768.public_key_size;
    const SECRET_KEY_BYTES: usize = global_params::KYBER768.secret_key_size;
    const CIPHERTEXT_BYTES: usize = global_params::KYBER768.ciphertext_size;
}

pub struct Kyber1024ParamsImpl;
impl KyberParams for Kyber1024ParamsImpl {
    const K: usize = global_params::KYBER1024.k;
    const ETA1: u8 = global_params::KYBER1024.eta1;
    const ETA2: u8 = global_params::KYBER1024.eta2;
    const DU: usize = global_params::KYBER1024.du;
    const DV: usize = global_params::KYBER1024.dv;
    const NAME: &'static str = "Kyber-1024";
    const PUBLIC_KEY_BYTES: usize = global_params::KYBER1024.public_key_size;
    const SECRET_KEY_BYTES: usize = global_params::KYBER1024.secret_key_size;
    const CIPHERTEXT_BYTES: usize = global_params::KYBER1024.ciphertext_size;
}

// Helper: Symmetric key seed size
pub const KYBER_SYMKEY_SEED_BYTES: usize = 32;
// Helper: Rho seed size (for matrix A)
pub const KYBER_RHO_SEED_BYTES: usize = 32;
// Helper: Noise seed size
pub const KYBER_NOISE_SEED_BYTES: usize = 32;