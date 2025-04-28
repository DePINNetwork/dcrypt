//! Integration tests for Key Encapsulation Mechanisms

use dcrypt::prelude::*;
use dcrypt::kem::{RsaKem2048, Kyber768, NtruHps};
use dcrypt::hybrid::kem::RsaKyberHybrid;
use rand::rngs::OsRng;

#[test]
fn test_rsa_kem() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (public_key, secret_key) = RsaKem2048::keypair(&mut rng).unwrap();
    
    // Encapsulate
    let (ciphertext, shared_secret_sender) = RsaKem2048::encapsulate(&mut rng, &public_key).unwrap();
    
    // Decapsulate
    let shared_secret_recipient = RsaKem2048::decapsulate(&secret_key, &ciphertext).unwrap();
    
    // Verify shared secrets match
    assert_eq!(
        shared_secret_sender.as_ref(),
        shared_secret_recipient.as_ref()
    );
}

#[test]
fn test_kyber_kem() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (public_key, secret_key) = Kyber768::keypair(&mut rng).unwrap();
    
    // Encapsulate
    let (ciphertext, shared_secret_sender) = Kyber768::encapsulate(&mut rng, &public_key).unwrap();
    
    // Decapsulate
    let shared_secret_recipient = Kyber768::decapsulate(&secret_key, &ciphertext).unwrap();
    
    // Verify shared secrets match
    assert_eq!(
        shared_secret_sender.as_ref(),
        shared_secret_recipient.as_ref()
    );
}

#[test]
fn test_ntru_kem() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (public_key, secret_key) = NtruHps::keypair(&mut rng).unwrap();
    
    // Encapsulate
    let (ciphertext, shared_secret_sender) = NtruHps::encapsulate(&mut rng, &public_key).unwrap();
    
    // Decapsulate
    let shared_secret_recipient = NtruHps::decapsulate(&secret_key, &ciphertext).unwrap();
    
    // Verify shared secrets match
    assert_eq!(
        shared_secret_sender.as_ref(),
        shared_secret_recipient.as_ref()
    );
}

#[test]
fn test_hybrid_kem() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (public_key, secret_key) = RsaKyberHybrid::keypair(&mut rng).unwrap();
    
    // Encapsulate
    let (ciphertext, shared_secret_sender) = RsaKyberHybrid::encapsulate(&mut rng, &public_key).unwrap();
    
    // Decapsulate
    let shared_secret_recipient = RsaKyberHybrid::decapsulate(&secret_key, &ciphertext).unwrap();
    
    // Verify shared secrets match
    assert_eq!(
        shared_secret_sender.as_ref(),
        shared_secret_recipient.as_ref()
    );
}
