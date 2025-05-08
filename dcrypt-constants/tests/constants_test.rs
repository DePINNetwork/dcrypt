// Test importing and accessing various constants

// Traditional cryptography constants
use dcrypt_constants::traditional::rsa::{
    RSA_MODULUS_2048, RSA_MODULUS_4096, RSA_PUBLIC_EXPONENT
};
use dcrypt_constants::traditional::ed25519::{
    ED25519_PUBLIC_KEY_SIZE, ED25519_SECRET_KEY_SIZE, ED25519_SIGNATURE_SIZE
};
use dcrypt_constants::traditional::ecdsa::NIST_P256;

// Post-quantum cryptography constants
use dcrypt_constants::pqc::kyber::{KYBER_N, KYBER_Q, KYBER768};
use dcrypt_constants::pqc::dilithium::{DILITHIUM_N, DILITHIUM_Q, DILITHIUM3};
use dcrypt_constants::pqc::ntru::NTRU_HPS_2048_509;

// Utility constants
use dcrypt_constants::utils::hash::SHA256_OUTPUT_SIZE;
use dcrypt_constants::utils::symmetric::{AES256_KEY_SIZE, CHACHA20_KEY_SIZE};

#[test]
fn test_rsa_constants() {
    assert_eq!(RSA_MODULUS_2048, 2048);
    assert_eq!(RSA_MODULUS_4096, 4096);
    assert_eq!(RSA_PUBLIC_EXPONENT, 65537);
}

#[test]
fn test_ed25519_constants() {
    assert_eq!(ED25519_PUBLIC_KEY_SIZE, 32);
    assert_eq!(ED25519_SECRET_KEY_SIZE, 32);
    assert_eq!(ED25519_SIGNATURE_SIZE, 64);
}

#[test]
fn test_ecdsa_constants() {
    assert_eq!(NIST_P256.h, 1); // Cofactor
    assert_eq!(NIST_P256.p[0], 0xFF); // First byte of prime
}

#[test]
fn test_kyber_constants() {
    assert_eq!(KYBER_N, 256);
    assert_eq!(KYBER_Q, 3329);
    assert_eq!(KYBER768.k, 3);
    assert_eq!(KYBER768.shared_secret_size, 32);
}

#[test]
fn test_dilithium_constants() {
    assert_eq!(DILITHIUM_N, 256);
    assert_eq!(DILITHIUM_Q, 8380417);
    assert_eq!(DILITHIUM3.k, 6);
    assert_eq!(DILITHIUM3.l, 5);
}

#[test]
fn test_ntru_constants() {
    assert_eq!(NTRU_HPS_2048_509.n, 509);
    assert_eq!(NTRU_HPS_2048_509.q, 2048);
    assert_eq!(NTRU_HPS_2048_509.shared_secret_size, 32);
}

#[test]
fn test_utility_constants() {
    assert_eq!(SHA256_OUTPUT_SIZE, 32);
    assert_eq!(AES256_KEY_SIZE, 32);
    assert_eq!(CHACHA20_KEY_SIZE, 32);
}