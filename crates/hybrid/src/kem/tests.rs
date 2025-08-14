// File: crates/hybrid/src/kem/tests.rs

use super::{EcdhP256Kyber768, EcdhP384Kyber1024};
use dcrypt_api::{Kem, Serialize}; // CORRECT: Add Serialize to the use statement
use rand::rngs::OsRng;

#[test]
fn test_ecdh_p256_kyber_768_kem_full_roundtrip() {
    let mut rng = OsRng;
    let (pk, sk) = EcdhP256Kyber768::keypair(&mut rng).expect("Keypair generation failed");

    // Encapsulate and Decapsulate
    let (ciphertext, ss_sender) = EcdhP256Kyber768::encapsulate(&mut rng, &pk).unwrap();
    let ss_recipient = EcdhP256Kyber768::decapsulate(&sk, &ciphertext).unwrap();

    // Verify secrets match and have correct length
    assert_eq!(*ss_sender.to_bytes_zeroizing(), *ss_recipient.to_bytes_zeroizing());
    assert_eq!(ss_sender.len(), 32);

    // Verify key and ciphertext lengths (Now compiles because `to_bytes` is in scope)
    assert_eq!(pk.to_bytes().len(), 1217);
    assert_eq!(ciphertext.to_bytes().len(), 1121);
}

#[test]
fn test_ecdh_p384_kyber_1024_kem_full_roundtrip() {
    let mut rng = OsRng;
    let (pk, sk) = EcdhP384Kyber1024::keypair(&mut rng).expect("Keypair generation failed");

    // Encapsulate and Decapsulate
    let (ciphertext, ss_sender) = EcdhP384Kyber1024::encapsulate(&mut rng, &pk).unwrap();
    let ss_recipient = EcdhP384Kyber1024::decapsulate(&sk, &ciphertext).unwrap();

    // Verify secrets match and have correct length
    assert_eq!(*ss_sender.to_bytes_zeroizing(), *ss_recipient.to_bytes_zeroizing());
    assert_eq!(ss_sender.len(), 32);

    // Verify key and ciphertext lengths (Now compiles because `to_bytes` is in scope)
    assert_eq!(pk.to_bytes().len(), 1617);
    assert_eq!(ciphertext.to_bytes().len(), 1617);
}

#[test]
fn test_hybrid_kem_decapsulation_wrong_key() {
    let mut rng = OsRng;
    let (pk1, _) = EcdhP256Kyber768::keypair(&mut rng).unwrap();
    let (_, sk2) = EcdhP256Kyber768::keypair(&mut rng).unwrap();

    let (ciphertext, ss_sender) = EcdhP256Kyber768::encapsulate(&mut rng, &pk1).unwrap();
    let ss_recipient = EcdhP256Kyber768::decapsulate(&sk2, &ciphertext).unwrap();

    assert_ne!(*ss_sender.to_bytes_zeroizing(), *ss_recipient.to_bytes_zeroizing());
}

#[test]
fn test_hybrid_serialization_roundtrip() {
    let mut rng = OsRng;
    let (pk, _) = EcdhP384Kyber1024::keypair(&mut rng).unwrap();
    let (ct, _) = EcdhP384Kyber1024::encapsulate(&mut rng, &pk).unwrap();

    // Public Key roundtrip (Now compiles because trait methods are in scope)
    let pk_bytes = pk.to_bytes();
    let pk_restored =
        <EcdhP384Kyber1024 as Kem>::PublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk.to_bytes(), pk_restored.to_bytes());

    // Ciphertext roundtrip (Now compiles because trait methods are in scope)
    let ct_bytes = ct.to_bytes();
    let ct_restored =
        <EcdhP384Kyber1024 as Kem>::Ciphertext::from_bytes(&ct_bytes).unwrap();
    assert_eq!(ct.to_bytes(), ct_restored.to_bytes());
}

#[test]
fn test_serialization_invalid_length_errors() {
    // Public Key for EcdhP256Kyber768 (len 1217)
    let too_short_pk = vec![0u8; 100];
    assert!(<EcdhP256Kyber768 as Kem>::PublicKey::from_bytes(&too_short_pk).is_err());
    let too_long_pk = vec![0u8; 2000];
    assert!(<EcdhP256Kyber768 as Kem>::PublicKey::from_bytes(&too_long_pk).is_err());

    // Ciphertext for EcdhP384Kyber1024 (len 1617)
    let too_short_ct = vec![0u8; 100];
    assert!(<EcdhP384Kyber1024 as Kem>::Ciphertext::from_bytes(&too_short_ct).is_err());
    let too_long_ct = vec![0u8; 2000];
    assert!(<EcdhP384Kyber1024 as Kem>::Ciphertext::from_bytes(&too_long_ct).is_err());
}