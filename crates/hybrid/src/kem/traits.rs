// File: crates/hybrid/src/kem/traits.rs

//! Defines traits for extending KEM functionality within the hybrid crate.

use dcrypt_api::Kem;
use dcrypt_kem::{ecdh, kyber};

/// Extends the `dcrypt_api::Kem` trait with compile-time length constants.
/// This is essential for generic serialization of hybrid data structures.
pub trait KemDimensions: Kem {
    /// The byte length of the public key.
    const PUBLIC_KEY_LEN: usize;
    /// The byte length of the secret key.
    const SECRET_KEY_LEN: usize;
    /// The byte length of the ciphertext.
    const CIPHERTEXT_LEN: usize;
}

// --- ECDH Implementations ---
impl KemDimensions for ecdh::EcdhP192 {
    const PUBLIC_KEY_LEN: usize = 25;
    const SECRET_KEY_LEN: usize = 24;
    const CIPHERTEXT_LEN: usize = 25;
}
impl KemDimensions for ecdh::EcdhP224 {
    const PUBLIC_KEY_LEN: usize = 29;
    const SECRET_KEY_LEN: usize = 28;
    const CIPHERTEXT_LEN: usize = 45; // Authenticated ciphertext (29-byte key + 16-byte tag)
}
impl KemDimensions for ecdh::EcdhP256 {
    const PUBLIC_KEY_LEN: usize = 33;
    const SECRET_KEY_LEN: usize = 32;
    const CIPHERTEXT_LEN: usize = 33;
}
impl KemDimensions for ecdh::EcdhP384 {
    const PUBLIC_KEY_LEN: usize = 49;
    const SECRET_KEY_LEN: usize = 48;
    const CIPHERTEXT_LEN: usize = 49;
}
impl KemDimensions for ecdh::EcdhP521 {
    const PUBLIC_KEY_LEN: usize = 67;
    const SECRET_KEY_LEN: usize = 66;
    const CIPHERTEXT_LEN: usize = 67;
}
impl KemDimensions for ecdh::EcdhK256 {
    const PUBLIC_KEY_LEN: usize = 33;
    const SECRET_KEY_LEN: usize = 32;
    const CIPHERTEXT_LEN: usize = 33;
}
impl KemDimensions for ecdh::EcdhB283k {
    const PUBLIC_KEY_LEN: usize = 37;
    const SECRET_KEY_LEN: usize = 36;
    const CIPHERTEXT_LEN: usize = 37;
}

// --- Kyber Implementations ---
impl KemDimensions for kyber::Kyber512 {
    const PUBLIC_KEY_LEN: usize = 800;
    const SECRET_KEY_LEN: usize = 1632;
    const CIPHERTEXT_LEN: usize = 768;
}
impl KemDimensions for kyber::Kyber768 {
    const PUBLIC_KEY_LEN: usize = 1184;
    const SECRET_KEY_LEN: usize = 2400;
    const CIPHERTEXT_LEN: usize = 1088;
}
impl KemDimensions for kyber::Kyber1024 {
    const PUBLIC_KEY_LEN: usize = 1568;
    const SECRET_KEY_LEN: usize = 3168;
    const CIPHERTEXT_LEN: usize = 1568;
}