//! Integration tests for Key Derivation Functions
//!
//! This module provides integration tests that validate the correctness and
//! interoperability of the KDF implementations against known test vectors.

use crate::kdf::*;
use crate::hash::{Sha1, Sha256, Sha512};
use hex;

#[test]
fn test_hkdf_sha256_trait() {
    // Test KDF trait implementation for HKDF
    let kdf = Hkdf::<Sha256>::new();
    
    let input = b"input key material";
    let salt = b"salt";
    let info = b"info";
    let length = 32;
    
    let key = kdf.derive_key(input, Some(salt), Some(info), length).unwrap();
    assert_eq!(key.len(), length);
    
    // Compare with direct call
    let key2 = Hkdf::<Sha256>::derive(Some(salt), input, Some(info), length).unwrap();
    assert_eq!(key, key2);
}

#[test]
fn test_pbkdf2_sha256_trait() {
    // Test KDF trait implementation for PBKDF2
    let kdf = Pbkdf2::<Sha256>::new();
    
    let password = b"password";
    let salt = b"salt";
    let length = 32;
    
    let key = kdf.derive_key(password, Some(salt), None, length).unwrap();
    assert_eq!(key.len(), length);
    
    // Compare with direct call
    let params = Pbkdf2Params {
        salt: salt.to_vec(),
        iterations: 10000, // Default from Pbkdf2Params
        key_length: length,
    };
    
    let pbkdf2 = Pbkdf2::<Sha256>::new_with_params(params);
    let key2 = pbkdf2.derive_key_with_options(password, None, None, None).unwrap();
    
    assert_eq!(key, key2);
}

#[test]
fn test_argon2_trait() {
    // Test KDF trait implementation for Argon2
    let kdf = Argon2::new();
    
    let password = b"password";
    let salt = b"somesalt";
    let length = 32;
    
    let key = kdf.derive_key(password, Some(salt), None, length).unwrap();
    assert_eq!(key.len(), length);
    
    // Compare with direct call
    let params = Argon2Params {
        argon_type: Argon2Type::Argon2i, // Default type
        memory_cost: 4096,               // Default memory cost
        time_cost: 3,                    // Default time cost
        parallelism: 1,                  // Default parallelism
        salt: salt.to_vec(),
        ad: None,
        output_len: length,
    };
    
    let argon2 = Argon2::new_with_params(params);
    let key2 = argon2.hash_password(password).unwrap();
    
    assert_eq!(key, key2);
}

#[test]
fn test_kdf_interoperability() {
    // Test that different KDFs produce different outputs for the same input
    let input = b"same input for all KDFs";
    let salt = b"same salt";
    let length = 32;
    
    // Generate keys with different KDFs
    let hkdf_key = Hkdf::<Sha256>::derive(Some(salt), input, None, length).unwrap();
    
    let pbkdf2_params = Pbkdf2Params {
        salt: salt.to_vec(),
        iterations: 1000, // Lower for testing
        key_length: length,
    };
    let pbkdf2 = Pbkdf2::<Sha256>::new_with_params(pbkdf2_params);
    let pbkdf2_key = pbkdf2.derive_key_with_options(input, None, None, None).unwrap();
    
    let argon2_params = Argon2Params {
        argon_type: Argon2Type::Argon2i,
        memory_cost: 64, // Lower for testing
        time_cost: 1,
        parallelism: 1,
        salt: salt.to_vec(),
        ad: None,
        output_len: length,
    };
    let argon2 = Argon2::new_with_params(argon2_params);
    let argon2_key = argon2.hash_password(input).unwrap();
    
    // All keys should be different
    assert_ne!(hkdf_key, pbkdf2_key);
    assert_ne!(hkdf_key, argon2_key);
    assert_ne!(pbkdf2_key, argon2_key);
}

mod vectors;