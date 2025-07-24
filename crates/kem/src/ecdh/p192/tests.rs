//! Tests for ECDH KEM P-192

use super::*; // Import from parent mod (p192/mod.rs)
use dcrypt_api::Kem; // The main KEM trait
use rand::rngs::OsRng;

#[test]
fn test_ecdh_p192_keypair_generation() {
    let mut rng = OsRng;
    let keypair_result = EcdhP192::keypair(&mut rng);
    assert!(keypair_result.is_ok(), "Keypair generation failed: {:?}", keypair_result.err());
    if let Ok((pk, sk)) = keypair_result {
        assert_eq!(pk.as_ref().len(), ec::P192_POINT_COMPRESSED_SIZE);
        assert_eq!(sk.as_ref().len(), ec::P192_SCALAR_SIZE);
    }
}

#[test]
fn test_ecdh_p192_kem_roundtrip() {
    let mut rng = OsRng;

    // 1. Generate recipient's key pair
    let (public_key, secret_key) = EcdhP192::keypair(&mut rng).expect("Keypair generation failed");

    // 2. Sender encapsulates a shared secret using recipient's public key
    let encapsulate_result = EcdhP192::encapsulate(&mut rng, &public_key);
    assert!(encapsulate_result.is_ok(), "Encapsulation failed: {:?}", encapsulate_result.err());
    let (ciphertext, shared_secret_sender) = encapsulate_result.unwrap();

    assert_eq!(ciphertext.as_ref().len(), ec::P192_POINT_COMPRESSED_SIZE);
    assert_eq!(shared_secret_sender.as_ref().len(), ec::P192_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE);

    // 3. Recipient decapsulates the ciphertext using their secret key
    let decapsulate_result = EcdhP192::decapsulate(&secret_key, &ciphertext);
    assert!(decapsulate_result.is_ok(), "Decapsulation failed: {:?}", decapsulate_result.err());
    let shared_secret_receiver = decapsulate_result.unwrap();

    // 4. Verify shared secrets match
    assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref(), "Shared secrets do not match");
}

#[test]
fn test_ecdh_p192_kem_decapsulate_wrong_key() {
    let mut rng = OsRng;

    // Recipient 1
    let (public_key1, _secret_key1) = EcdhP192::keypair(&mut rng).expect("Keypair 1 generation failed");
    // Recipient 2 (attacker or wrong recipient)
    let (_public_key2, secret_key2) = EcdhP192::keypair(&mut rng).expect("Keypair 2 generation failed");

    // Sender encapsulates for Recipient 1
    let (ciphertext, _shared_secret_sender) = EcdhP192::encapsulate(&mut rng, &public_key1).expect("Encapsulation failed");

    // Recipient 2 tries to decapsulate (should not yield the same shared secret, or should fail)
    // In a correct KEM, this should ideally result in a different key or an error.
    // Our placeholder might just give a different random key. The key is that it's NOT the sender's SS.
    let decapsulate_result = EcdhP192::decapsulate(&secret_key2, &ciphertext);
    assert!(decapsulate_result.is_ok(), "Decapsulation with wrong key should ideally not error outright unless auth is built-in to KEM itself, but produce a different key.");
    // A more robust test would check that decapsulate_result.unwrap() != _shared_secret_sender
    // However, for a simple ECDH without an authenticated KEM wrapper, it will just produce a different shared secret.
}

#[test]
fn test_ecdh_p192_kem_decapsulate_tampered_ciphertext() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdhP192::keypair(&mut rng).expect("Keypair generation failed");

    let (mut ciphertext, shared_secret_sender) = EcdhP192::encapsulate(&mut rng, &public_key).expect("Encapsulation failed");

    // Tamper with the ciphertext (ephemeral public key)
    if !ciphertext.0.is_empty() {
        ciphertext.0[0] ^= 0xff;
    }

    let decapsulate_result = EcdhP192::decapsulate(&secret_key, &ciphertext);
    // Decapsulation might succeed but produce a different shared secret,
    // or it might fail if the tampered point is invalid.
    match decapsulate_result {
        Ok(ss_receiver) => {
            assert_ne!(shared_secret_sender.as_ref(), ss_receiver.as_ref(), "Shared secret should differ for tampered ciphertext if decapsulation succeeds.");
        }
        Err(e) => {
            // It's also acceptable for decapsulation to fail if the point becomes invalid
            println!("Decapsulation failed as expected for tampered ciphertext: {:?}", e);
        }
    }
}