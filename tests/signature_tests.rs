//! Integration tests for Digital Signature Schemes

use dcrypt::prelude::*;
use dcrypt::sign::{Ed25519, Dilithium3, Falcon512};
use dcrypt::hybrid::sign::EcdsaDilithiumHybrid;
use rand::rngs::OsRng;

#[test]
fn test_ed25519_signature() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (public_key, secret_key) = Ed25519::keypair(&mut rng).unwrap();
    
    // Message to sign
    let message = b"Test message for Ed25519 signature";
    
    // Sign the message
    let signature = Ed25519::sign(message, &secret_key).unwrap();
    
    // Verify the signature
    let result = Ed25519::verify(message, &signature, &public_key);
    assert!(result.is_ok());
    
    // Try with a modified message
    let modified_message = b"Modified message that should not verify";
    let result = Ed25519::verify(modified_message, &signature, &public_key);
    assert!(result.is_err());
}

#[test]
fn test_dilithium_signature() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (public_key, secret_key) = Dilithium3::keypair(&mut rng).unwrap();
    
    // Message to sign
    let message = b"Test message for Dilithium signature";
    
    // Sign the message
    let signature = Dilithium3::sign(message, &secret_key).unwrap();
    
    // Verify the signature
    let result = Dilithium3::verify(message, &signature, &public_key);
    assert!(result.is_ok());
}

#[test]
fn test_falcon_signature() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (public_key, secret_key) = Falcon512::keypair(&mut rng).unwrap();
    
    // Message to sign
    let message = b"Test message for Falcon signature";
    
    // Sign the message
    let signature = Falcon512::sign(message, &secret_key).unwrap();
    
    // Verify the signature
    let result = Falcon512::verify(message, &signature, &public_key);
    assert!(result.is_ok());
}

#[test]
fn test_hybrid_signature() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (public_key, secret_key) = EcdsaDilithiumHybrid::keypair(&mut rng).unwrap();
    
    // Message to sign
    let message = b"Test message for hybrid signature";
    
    // Sign the message
    let signature = EcdsaDilithiumHybrid::sign(message, &secret_key).unwrap();
    
    // Verify the signature
    let result = EcdsaDilithiumHybrid::verify(message, &signature, &public_key);
    assert!(result.is_ok());
}
