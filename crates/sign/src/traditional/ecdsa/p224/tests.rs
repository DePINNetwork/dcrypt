use super::*;
use dcrypt_api::Signature as SignatureTrait;
use rand::rngs::OsRng;

#[test]
fn test_ecdsa_p224_keypair_generation() {
    let keypair_result = EcdsaP224::keypair(&mut OsRng);
    assert!(keypair_result.is_ok(), "Keypair generation failed: {:?}", keypair_result.err());
    let (pk, sk) = keypair_result.unwrap();
    assert_eq!(pk.as_ref().len(), ec::P224_POINT_UNCOMPRESSED_SIZE);
    assert_eq!(sk.as_ref().len(), ec::P224_SCALAR_SIZE);
}

#[test]
fn test_ecdsa_p224_sign_verify_roundtrip() {
    let (pk, sk) = EcdsaP224::keypair(&mut OsRng).expect("Keygen failed");
    let message = b"This is a test message for ECDSA P-224.";

    let signature_result = EcdsaP224::sign(message, &sk);
    assert!(signature_result.is_ok(), "Signing failed: {:?}", signature_result.err());
    let signature = signature_result.unwrap();

    let verification_result = EcdsaP224::verify(message, &signature, &pk);
    assert!(verification_result.is_ok(), "Verification failed: {:?}", verification_result.err());
}

#[test]
fn test_ecdsa_p224_verify_tampered_message() {
    let (pk, sk) = EcdsaP224::keypair(&mut OsRng).expect("Keygen failed");
    let message = b"Original message.";
    let tampered_message = b"Tampered message!";

    let signature = EcdsaP224::sign(message, &sk).expect("Signing failed");

    let verification_result = EcdsaP224::verify(tampered_message, &signature, &pk);
    assert!(verification_result.is_err(), "Verification should fail for tampered message");
}

#[test]
fn test_ecdsa_p224_verify_tampered_signature() {
    let (pk, sk) = EcdsaP224::keypair(&mut OsRng).expect("Keygen failed");
    let message = b"Another test message.";

    let mut signature_vec = EcdsaP224::sign(message, &sk).expect("Signing failed").0;
    if !signature_vec.is_empty() {
        signature_vec[0] ^= 0xFF; 
    }
    let tampered_signature_data = EcdsaP224Signature(signature_vec);

    let verification_result = EcdsaP224::verify(message, &tampered_signature_data, &pk);
    assert!(verification_result.is_err(), "Verification should fail for tampered signature");
}

#[test]
fn test_ecdsa_p224_verify_wrong_public_key() {
    let (_pk1, sk1) = EcdsaP224::keypair(&mut OsRng).expect("Keygen1 failed");
    let (pk2, _sk2) = EcdsaP224::keypair(&mut OsRng).expect("Keygen2 failed");
    let message = b"Message signed with key1.";

    let signature = EcdsaP224::sign(message, &sk1).expect("Signing failed");

    let verification_result = EcdsaP224::verify(message, &signature, &pk2);
    assert!(verification_result.is_err(), "Verification should fail with wrong public key");
}