use super::ecdh_kyber::{EcdhKyber768, HybridCiphertext, HybridPublicKey};
use dcrypt_api::Kem;
use rand::rngs::OsRng;

#[test]
fn test_hybrid_kem_keypair_generation() {
    let mut rng = OsRng;
    let keypair_result = EcdhKyber768::keypair(&mut rng);
    assert!(keypair_result.is_ok(), "Hybrid keypair generation failed");

    let (pk, sk) = keypair_result.unwrap();
    // ECDH P-256 (33) + Kyber-768 (1184) = 1217
    assert_eq!(pk.to_bytes().len(), 1217);
    // ECDH P-256 (32) + Kyber-768 (2400) = 2432
    assert_eq!(sk.ecdh_sk.to_bytes().len() + sk.kyber_sk.to_bytes_zeroizing().len(), 2432);
}

#[test]
fn test_hybrid_kem_full_roundtrip() {
    let mut rng = OsRng;

    // 1. Generate keypair
    let (pk, sk) = EcdhKyber768::keypair(&mut rng).expect("Keypair generation failed");

    // 2. Encapsulate
    let (ciphertext, shared_secret_sender) =
        EcdhKyber768::encapsulate(&mut rng, &pk).expect("Encapsulation failed");

    // 3. Decapsulate
    let shared_secret_recipient =
        EcdhKyber768::decapsulate(&sk, &ciphertext).expect("Decapsulation failed");

    // 4. Verify secrets match
    assert_eq!(
        &*shared_secret_sender.to_bytes_zeroizing(),
        &*shared_secret_recipient.to_bytes_zeroizing()
    );
    assert_eq!(shared_secret_sender.len(), 32);

    // 5. Verify ciphertext length: ECDH P-256 (33) + Kyber-768 (1088) = 1121
    assert_eq!(ciphertext.to_bytes().len(), 1121);
}

#[test]
fn test_hybrid_kem_decapsulation_wrong_key() {
    let mut rng = OsRng;

    let (pk1, _) = EcdhKyber768::keypair(&mut rng).unwrap();
    let (_, sk2) = EcdhKyber768::keypair(&mut rng).unwrap();

    // Encapsulate for pk1
    let (ciphertext, shared_secret_sender) = EcdhKyber768::encapsulate(&mut rng, &pk1).unwrap();

    // Decapsulate with sk2
    let shared_secret_recipient = EcdhKyber768::decapsulate(&sk2, &ciphertext).unwrap();

    // Secrets must NOT match
    assert_ne!(
        &*shared_secret_sender.to_bytes_zeroizing(),
        &*shared_secret_recipient.to_bytes_zeroizing()
    );
}

#[test]
fn test_hybrid_serialization_roundtrip() {
    let mut rng = OsRng;
    let (pk, _) = EcdhKyber768::keypair(&mut rng).unwrap();
    let (ct, _) = EcdhKyber768::encapsulate(&mut rng, &pk).unwrap();

    // Public Key roundtrip
    let pk_bytes = pk.to_bytes();
    let pk_restored = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk.to_bytes(), pk_restored.to_bytes());

    // Ciphertext roundtrip
    let ct_bytes = ct.to_bytes();
    let ct_restored = HybridCiphertext::from_bytes(&ct_bytes).unwrap();
    assert_eq!(ct.to_bytes(), ct_restored.to_bytes());
}

#[test]
fn test_serialization_invalid_length_errors() {
    // Public Key
    let too_short_pk = vec![0u8; 100];
    assert!(HybridPublicKey::from_bytes(&too_short_pk).is_err());
    let too_long_pk = vec![0u8; 2000];
    assert!(HybridPublicKey::from_bytes(&too_long_pk).is_err());

    // Ciphertext
    let too_short_ct = vec![0u8; 100];
    assert!(HybridCiphertext::from_bytes(&too_short_ct).is_err());
    let too_long_ct = vec![0u8; 2000];
    assert!(HybridCiphertext::from_bytes(&too_long_ct).is_err());
}