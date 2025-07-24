// File: crates/kem/src/ecdh/b283k/tests.rs
use super::*;
use dcrypt_algorithms::ec::b283k as ec_b283k;
use dcrypt_api::Kem;
use rand::rngs::OsRng;

#[test]
fn test_b283k_kem_basic_flow() {
    let mut rng = OsRng;

    // Generate recipient keypair
    let (recipient_pk, recipient_sk) = EcdhB283k::keypair(&mut rng).unwrap();

    // Encapsulate
    let (ciphertext, shared_secret_sender) =
        EcdhB283k::encapsulate(&mut rng, &recipient_pk).unwrap();

    // Decapsulate
    let shared_secret_recipient = EcdhB283k::decapsulate(&recipient_sk, &ciphertext).unwrap();

    // Verify shared secrets match
    assert_eq!(
        shared_secret_sender.as_ref(),
        shared_secret_recipient.as_ref(),
        "Shared secrets should match"
    );

    // Verify key and ciphertext sizes
    assert_eq!(
        recipient_pk.as_ref().len(),
        ec_b283k::B283K_POINT_COMPRESSED_SIZE
    );
    assert_eq!(recipient_sk.as_ref().len(), ec_b283k::B283K_SCALAR_SIZE);
    assert_eq!(
        ciphertext.as_ref().len(),
        ec_b283k::B283K_POINT_COMPRESSED_SIZE
    );
    assert_eq!(
        shared_secret_sender.as_ref().len(),
        ec_b283k::B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE
    );
}

#[test]
fn test_b283k_kem_wrong_secret_key() {
    let mut rng = OsRng;

    // Generate two keypairs
    let (recipient_pk, _) = EcdhB283k::keypair(&mut rng).unwrap();
    let (_, wrong_sk) = EcdhB283k::keypair(&mut rng).unwrap();

    // Encapsulate to first recipient
    let (ciphertext, shared_secret_sender) =
        EcdhB283k::encapsulate(&mut rng, &recipient_pk).unwrap();

    // Try to decapsulate with wrong secret key
    let shared_secret_wrong = EcdhB283k::decapsulate(&wrong_sk, &ciphertext).unwrap();

    // Shared secrets should NOT match
    assert_ne!(
        shared_secret_sender.as_ref(),
        shared_secret_wrong.as_ref(),
        "Shared secrets should not match with wrong key"
    );
}

#[test]
fn test_b283k_kem_invalid_public_key() {
    let mut rng = OsRng;

    // Test with all-zero public key (invalid identity point encoding)
    let invalid_pk = EcdhB283kPublicKey([0u8; ec_b283k::B283K_POINT_COMPRESSED_SIZE]);

    // Encapsulation should fail
    let result = EcdhB283k::encapsulate(&mut rng, &invalid_pk);
    assert!(result.is_err());
}

#[test]
fn test_b283k_kem_tampered_ciphertext() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdhB283k::keypair(&mut rng).expect("Keypair generation failed");
    let (mut ciphertext, shared_secret_sender) =
        EcdhB283k::encapsulate(&mut rng, &public_key).expect("Encapsulation failed");

    // Tamper with the ciphertext
    ciphertext.0[5] ^= 0xff;

    let decapsulate_result = EcdhB283k::decapsulate(&secret_key, &ciphertext);

    match decapsulate_result {
        Ok(ss_receiver) => {
            assert_ne!(
                shared_secret_sender.as_ref(),
                ss_receiver.as_ref(),
                "Shared secret should differ for tampered ciphertext if decapsulation succeeds."
            );
        }
        Err(e) => {
            // It's also acceptable for decapsulation to fail if the point becomes invalid
            println!(
                "Decapsulation failed as expected for tampered ciphertext: {:?}",
                e
            );
        }
    }
}
