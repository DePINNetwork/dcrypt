use super::*;
use api::Kem as KemTrait; // Use the trait from api
use rand::rngs::OsRng;

#[test]
fn test_ecdh_p224_kem_keypair_generation() {
    let keypair_result = EcdhP224::keypair(&mut OsRng);
    assert!(keypair_result.is_ok(), "Keypair generation failed: {:?}", keypair_result.err());
    let (pk, sk) = keypair_result.unwrap();
    assert_eq!(pk.as_ref().len(), ec::P224_POINT_COMPRESSED_SIZE);
    assert_eq!(sk.as_ref().len(), ec::P224_SCALAR_SIZE);
}

#[test]
fn test_ecdh_p224_kem_encapsulate_decapsulate_roundtrip() {
    let (pk_r, sk_r) = EcdhP224::keypair(&mut OsRng).expect("Recipient keygen failed");

    let encapsulate_result = EcdhP224::encapsulate(&mut OsRng, &pk_r);
    assert!(encapsulate_result.is_ok(), "Encapsulation failed: {:?}", encapsulate_result.err());
    let (ciphertext, shared_secret_sender) = encapsulate_result.unwrap();

    // Fix: Check for full ciphertext size (compressed point + auth tag)
    assert_eq!(ciphertext.as_ref().len(), ec::P224_CIPHERTEXT_SIZE);
    assert_eq!(shared_secret_sender.as_ref().len(), ec::P224_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE);

    let decapsulate_result = EcdhP224::decapsulate(&sk_r, &ciphertext);
    assert!(decapsulate_result.is_ok(), "Decapsulation failed: {:?}", decapsulate_result.err());
    let shared_secret_receiver = decapsulate_result.unwrap();

    assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref(), "Shared secrets do not match");
}

#[test]
fn test_ecdh_p224_kem_decapsulate_wrong_secret_key() {
    let (pk_r, _sk_r1) = EcdhP224::keypair(&mut OsRng).expect("Recipient keygen1 failed");
    let (_pk_r2, sk_r2) = EcdhP224::keypair(&mut OsRng).expect("Recipient keygen2 failed"); // Different secret key

    let (ciphertext, _shared_secret_sender) = EcdhP224::encapsulate(&mut OsRng, &pk_r)
        .expect("Encapsulation failed");

    let decapsulate_result = EcdhP224::decapsulate(&sk_r2, &ciphertext); // Use wrong secret key
    assert!(decapsulate_result.is_err(), "Decapsulation should fail with wrong secret key");
    // More specific error check if desired, e.g., expecting a DecryptionFailed
}

#[test]
fn test_ecdh_p224_kem_decapsulate_tampered_ciphertext() {
    let (pk_r, sk_r) = EcdhP224::keypair(&mut OsRng).expect("Recipient keygen failed");

    let (mut ciphertext, _shared_secret_sender) = EcdhP224::encapsulate(&mut OsRng, &pk_r)
        .expect("Encapsulation failed");

    // Fix: Tamper with the first byte of the ephemeral public key portion
    // (avoiding accidental corruption of tag structure)
    ciphertext.0[0] ^= 0xFF;

    let decapsulate_result = EcdhP224::decapsulate(&sk_r, &ciphertext);
    assert!(decapsulate_result.is_err(), "Decapsulation should fail with tampered ciphertext");
}

#[test]
fn test_ecdh_p224_kem_ciphertext_structure() {
    let (pk_r, sk_r) = EcdhP224::keypair(&mut OsRng).expect("Recipient keygen failed");
    let (ciphertext, _shared_secret) = EcdhP224::encapsulate(&mut OsRng, &pk_r)
        .expect("Encapsulation failed");

    // Verify ciphertext structure: compressed point + auth tag
    assert_eq!(ciphertext.as_ref().len(), ec::P224_CIPHERTEXT_SIZE);
    assert_eq!(
        ciphertext.as_ref().len(), 
        ec::P224_POINT_COMPRESSED_SIZE + ec::P224_TAG_SIZE
    );
    
    // Verify the tag portion has the expected length
    let tag_portion = &ciphertext.as_ref()[ec::P224_POINT_COMPRESSED_SIZE..];
    assert_eq!(tag_portion.len(), ec::P224_TAG_SIZE);
}