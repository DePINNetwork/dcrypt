//! Integration tests for hybrid cryptographic schemes

use dcrypt::prelude::*;
use dcrypt::hybrid::kem::{RsaKyberHybrid, EcdhKyberHybrid, EcdhNtruHybrid};
use dcrypt::hybrid::sign::{EcdsaDilithiumHybrid, RsaFalconHybrid};
use dcrypt::symmetric::ChaCha20Poly1305;
use rand::rngs::OsRng;

#[test]
fn test_full_hybrid_encryption_workflow() {
    let mut rng = OsRng;
    
    // Generate hybrid KEM keypair
    let (public_key, secret_key) = EcdhKyberHybrid::keypair(&mut rng).unwrap();
    
    // Original message
    let message = b"This is a secret message protected by hybrid cryptography";
    
    // === Sender side ===
    
    // Encapsulate a shared secret
    let (ciphertext, shared_secret_sender) = 
        EcdhKyberHybrid::encapsulate(&mut rng, &public_key).unwrap();
    
    // Derive a symmetric key from the shared secret
    let key = ChaCha20Poly1305::derive_key_from_bytes(
        shared_secret_sender.as_ref()
    ).unwrap();
    
    // Generate a nonce
    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng).unwrap();
    
    // Encrypt the message
    let encrypted_message = ChaCha20Poly1305::encrypt(
        &key,
        &nonce,
        message,
        None
    ).unwrap();
    
    // === Recipient side ===
    
    // Decapsulate the same shared secret
    let shared_secret_recipient = 
        EcdhKyberHybrid::decapsulate(&secret_key, &ciphertext).unwrap();
    
    // Derive the same symmetric key
    let key_recipient = ChaCha20Poly1305::derive_key_from_bytes(
        shared_secret_recipient.as_ref()
    ).unwrap();
    
    // Decrypt the message
    let decrypted_message = ChaCha20Poly1305::decrypt(
        &key_recipient,
        &nonce,
        &encrypted_message,
        None
    ).unwrap();
    
    // Verify the decrypted message matches the original
    assert_eq!(message, &decrypted_message[..]);
}

#[test]
fn test_full_hybrid_signature_workflow() {
    let mut rng = OsRng;
    
    // Generate hybrid signature keypair
    let (public_key, secret_key) = 
        EcdsaDilithiumHybrid::keypair(&mut rng).unwrap();
    
    // Document to sign
    let document = b"Important document that needs long-term secure signatures";
    
    // Sign the document with hybrid signature
    let signature = 
        EcdsaDilithiumHybrid::sign(document, &secret_key).unwrap();
    
    // Verify the signature
    let result = 
        EcdsaDilithiumHybrid::verify(document, &signature, &public_key);
    
    assert!(result.is_ok());
}
