// File: crates/pke/src/ecies/p521/tests.rs
use super::*;
use rand::rngs::OsRng;
use api::error::Error as ApiError; // Alias for clarity
use crate::error::Error as PkeError; // Alias for clarity

#[test]
fn test_ecies_p521_keypair_generation() {
    let mut rng = OsRng;
    let result = EciesP521::keypair(&mut rng);
    assert!(result.is_ok(), "Keypair generation failed: {:?}", result.err());
    let (pk, sk) = result.unwrap();
    assert_eq!(pk.as_ref().len(), ec::P521_POINT_UNCOMPRESSED_SIZE);
    assert_eq!(sk.as_ref().len(), ec::P521_SCALAR_SIZE);
}

#[test]
fn test_ecies_p521_encrypt_decrypt_no_aad() {
    let mut rng = OsRng;
    let (pk, sk) = EciesP521::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b"Hello, ECIES P521!";
    let aad: Option<&[u8]> = None;

    let ciphertext_vec = EciesP521::encrypt(&pk, plaintext, aad, &mut rng)
        .expect("Encryption failed");

    let decrypted_plaintext = EciesP521::decrypt(&sk, &ciphertext_vec, aad)
        .expect("Decryption failed");

    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}

#[test]
fn test_ecies_p521_encrypt_decrypt_with_aad() {
    let mut rng = OsRng;
    let (pk, sk) = EciesP521::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b"Authenticated Encryption Test P521";
    let aad_data = *b"Some Associated Authenticated Data P521";
    let aad: Option<&[u8]> = Some(&aad_data);

    let ciphertext_vec = EciesP521::encrypt(&pk, plaintext, aad, &mut rng)
        .expect("Encryption with AAD failed");

    let decrypted_plaintext = EciesP521::decrypt(&sk, &ciphertext_vec, aad)
        .expect("Decryption with AAD failed");

    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}

#[test]
fn test_ecies_p521_decrypt_wrong_key() {
    let mut rng = OsRng;
    let (pk, _sk) = EciesP521::keypair(&mut rng).expect("Keypair generation failed");
    let (_pk_wrong, sk_wrong) = EciesP521::keypair(&mut rng).expect("Second keypair generation failed");
    let plaintext = b"Test with wrong key P521";
    let aad_data = *b"AAD for wrong key test P521";
    let aad: Option<&[u8]> = Some(&aad_data);

    let ciphertext_vec = EciesP521::encrypt(&pk, plaintext, aad, &mut rng)
        .expect("Encryption failed");

    let result = EciesP521::decrypt(&sk_wrong, &ciphertext_vec, aad);
    assert!(result.is_err(), "Decryption with wrong key should fail");

    match result.err().unwrap() {
        ApiError::DecryptionFailed { context, .. } => {
            assert!(context.contains("ECIES Decryption"));
        }
        e => panic!("Expected DecryptionFailed, got {:?}", e),
    }
}

#[test]
fn test_ecies_p521_decrypt_tampered_ciphertext() {
    let mut rng = OsRng;
    let (pk, sk) = EciesP521::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b"Do not tamper with this P521!";
    let aad_data = *b"Tamper test AAD P521";
    let aad: Option<&[u8]> = Some(&aad_data);

    let mut ciphertext_vec = EciesP521::encrypt(&pk, plaintext, aad, &mut rng)
        .expect("Encryption failed");

    if !ciphertext_vec.is_empty() {
        let last_byte_index = ciphertext_vec.len() - 1;
        ciphertext_vec[last_byte_index] ^= 0x01;
    }

    let result = EciesP521::decrypt(&sk, &ciphertext_vec, aad);
    assert!(result.is_err(), "Decryption of tampered ciphertext should fail");

    match result.err().unwrap() {
        ApiError::DecryptionFailed { context, .. } => {
            assert!(context.contains("ECIES Decryption"));
        }
        e => panic!("Expected DecryptionFailed due to tampering, got {:?}", e),
    }
}

#[test]
fn test_ecies_p521_decrypt_wrong_aad() {
    let mut rng = OsRng;
    let (pk, sk) = EciesP521::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b"AAD sensitivity test P521";
    let aad1_data = *b"Correct AAD P521";
    let aad1: Option<&[u8]> = Some(&aad1_data);
    let aad2_data = *b"Incorrect AAD P521";
    let aad2: Option<&[u8]> = Some(&aad2_data);

    let ciphertext_vec = EciesP521::encrypt(&pk, plaintext, aad1, &mut rng)
        .expect("Encryption failed");

    let result = EciesP521::decrypt(&sk, &ciphertext_vec, aad2);
    assert!(result.is_err(), "Decryption with wrong AAD should fail");

    match result.err().unwrap() {
        ApiError::DecryptionFailed { context, .. } => {
            assert!(context.contains("ECIES Decryption"));
        }
        e => panic!("Expected DecryptionFailed due to wrong AAD, got {:?}", e),
    }
}

#[test]
fn test_ecies_p521_invalid_public_key_for_encryption() {
    let mut rng = OsRng;
    let invalid_pk_bytes = [0u8; ec::P521_POINT_UNCOMPRESSED_SIZE]; // e.g., point at infinity (all zeros for uncompressed)
    let invalid_pk = EciesP521PublicKey(invalid_pk_bytes);
    let plaintext = b"Test invalid PK P521";
    let aad_data = *b"Invalid PK AAD P521";
    let aad: Option<&[u8]> = Some(&aad_data);

    let result = EciesP521::encrypt(&invalid_pk, plaintext, aad, &mut rng);
    assert!(result.is_err(), "Encryption with invalid public key should fail");
    
    match result.err().unwrap() {
        ApiError::Other { context, .. } if context == "ECIES Encryption" => {} 
        ApiError::InvalidKey { .. } => {} 
        e => panic!("Expected EncryptionFailed or InvalidKey, got {:?}", e),
    }
}

#[test]
fn test_ecies_p521_empty_plaintext() {
    let mut rng = OsRng;
    let (pk, sk) = EciesP521::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b""; // Empty plaintext
    let aad_data = *b"Empty plaintext AAD P521";
    let aad: Option<&[u8]> = Some(&aad_data);

    let ciphertext_vec = EciesP521::encrypt(&pk, plaintext, aad, &mut rng)
        .expect("Encryption of empty plaintext failed");

    let decrypted_plaintext = EciesP521::decrypt(&sk, &ciphertext_vec, aad)
        .expect("Decryption of empty plaintext failed");

    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}