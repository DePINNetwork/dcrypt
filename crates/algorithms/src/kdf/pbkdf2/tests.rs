use super::*;
use crate::hash::{Sha1, Sha256, Sha512};
use crate::kdf::Pbkdf2; 
use crate::kdf::Pbkdf2Params;
use crate::kdf::params::ParamProvider;
use crate::kdf::KeyDerivationFunction;
use crate::types::Salt;
use hex;

/// Test PBKDF2-HMAC-SHA1 against RFC 6070 Test Case 1
/// 
/// RFC 6070 provides official test vectors for PBKDF2.
/// This test verifies the implementation with 1 iteration.
#[test]
fn test_pbkdf2_sha1_rfc6070_1() {
    // Test case 1 from RFC 6070
    let password = b"password";
    let salt = b"salt";
    let iterations = 1;
    let key_length = 20;
    
    let expected = hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6").unwrap();
    
    let derived = Pbkdf2::<Sha1>::pbkdf2(password, salt, iterations, key_length).unwrap();
    assert_eq!(derived.as_slice(), expected.as_slice());
}

/// Test PBKDF2-HMAC-SHA1 against RFC 6070 Test Case 2
/// 
/// This test verifies the implementation with 2 iterations.
#[test]
fn test_pbkdf2_sha1_rfc6070_2() {
    // Test case 2 from RFC 6070
    let password = b"password";
    let salt = b"salt";
    let iterations = 2;
    let key_length = 20;
    
    let expected = hex::decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957").unwrap();
    
    let derived = Pbkdf2::<Sha1>::pbkdf2(password, salt, iterations, key_length).unwrap();
    assert_eq!(derived.as_slice(), expected.as_slice());
}

/// Test PBKDF2-HMAC-SHA1 against RFC 6070 Test Case 3
/// 
/// This test verifies the implementation with a more realistic
/// number of iterations (4096).
#[test]
fn test_pbkdf2_sha1_rfc6070_3() {
    // Test case 3 from RFC 6070
    let password = b"password";
    let salt = b"salt";
    let iterations = 4096;
    let key_length = 20;
    
    let expected = hex::decode("4b007901b765489abead49d926f721d065a429c1").unwrap();
    
    let derived = Pbkdf2::<Sha1>::pbkdf2(password, salt, iterations, key_length).unwrap();
    assert_eq!(derived.as_slice(), expected.as_slice());
}

/// Test PBKDF2-HMAC-SHA1 against RFC 6070 Test Case 4
/// 
/// This test verifies the implementation with a very high
/// iteration count (16,777,216). Note that this test is 
/// ignored by default as it takes a long time to run.
#[test]
#[ignore]  // This test takes a long time to run
fn test_pbkdf2_sha1_rfc6070_4() {
    // Test case 4 from RFC 6070
    let password = b"password";
    let salt = b"salt";
    let iterations = 16_777_216;
    let key_length = 20;
    
    let expected = hex::decode("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984").unwrap();
    
    let derived = Pbkdf2::<Sha1>::pbkdf2(password, salt, iterations, key_length).unwrap();
    assert_eq!(derived.as_slice(), expected.as_slice());
}

/// Test PBKDF2-HMAC-SHA1 against RFC 6070 Test Case 5
/// 
/// This test verifies the implementation with longer inputs
/// (longer password and salt)
#[test]
fn test_pbkdf2_sha1_rfc6070_5() {
    // Test case 5 from RFC 6070
    let password = b"passwordPASSWORDpassword";
    let salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
    let iterations = 4096;
    let key_length = 25;
    
    let expected = hex::decode("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038").unwrap();
    
    let derived = Pbkdf2::<Sha1>::pbkdf2(password, salt, iterations, key_length).unwrap();
    assert_eq!(derived.as_slice(), expected.as_slice());
}

/// Test PBKDF2-HMAC-SHA1 against RFC 6070 Test Case 6
/// 
/// This test verifies the implementation with inputs
/// containing zero bytes.
#[test]
fn test_pbkdf2_sha1_rfc6070_6() {
    // Test case 6 from RFC 6070
    let password = b"pass\0word";
    let salt = b"sa\0lt";
    let iterations = 4096;
    let key_length = 16;
    
    let expected = hex::decode("56fa6aa75548099dcc37d7f03425e0c3").unwrap();
    
    let derived = Pbkdf2::<Sha1>::pbkdf2(password, salt, iterations, key_length).unwrap();
    assert_eq!(derived.as_slice(), expected.as_slice());
}

/// Test PBKDF2 with SHA-256
/// 
/// This test verifies the implementation works with SHA-256.
/// The expected value was generated with OpenSSL.
#[test]
fn test_pbkdf2_sha256() {
    // Test case with SHA-256 (not part of RFC, but using common parameters)
    let password = b"password";
    let salt = b"salt";
    let iterations = 4096;
    let key_length = 32;
    
    // Expected value generated with OpenSSL
    let expected = hex::decode("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a").unwrap();
    
    let derived = Pbkdf2::<Sha256>::pbkdf2(password, salt, iterations, key_length).unwrap();
    assert_eq!(derived.as_slice(), expected.as_slice());
}

/// Test PBKDF2 with SHA-512
/// 
/// This test verifies the implementation works with SHA-512.
/// The expected value was generated with OpenSSL.
#[test]
fn test_pbkdf2_sha512() {
    // Test case with SHA-512 (not part of RFC, but using common parameters)
    let password = b"password";
    let salt = b"salt";
    let iterations = 1000;
    let key_length = 64;
    
    // Expected value generated with OpenSSL
    // Correct SHA-512 PBKDF2-HMAC output for 1000 iterations
    let expected = hex::decode(
        "afe6c5530785b6cc6b1c6453384731bd5ee432ee549fd42fb6695779ad8a1c5bf59de69c48f774efc4007d5298f9033c0241d5ab69305e7b64eceeb8d834cfec"
    ).unwrap();

    let derived = Pbkdf2::<Sha512>::pbkdf2(password, salt, iterations, key_length).unwrap();
    assert_eq!(derived.as_slice(), expected.as_slice());
}

/// Test the object-oriented PBKDF2 interface
/// 
/// This test verifies that the object-oriented interface works correctly,
/// including parameter storage and overriding.
#[test]
fn test_pbkdf2_object_interface() {
    // Test using the object-oriented interface
    let password = b"password";
    let salt_data = b"salt";
    let iterations = 1000;
    let key_length = 32;
    
    // Create a Salt<16> from the test vector
    // Using 16 bytes since that's the minimum salt size required by PBKDF2
    let mut salt_array = [0u8; 16];
    salt_array[..salt_data.len()].copy_from_slice(salt_data);
    let salt = Salt::<16>::new(salt_array);
    
    // Create with params
    let params = Pbkdf2Params {
        salt,
        iterations,
        key_length,
    };
    
    let pbkdf2 = Pbkdf2::<Sha256, 16>::with_params(params);
    
    // Derive using the stored parameters
    let key1 = pbkdf2.derive_key(password, None, None, 0).unwrap();
    assert_eq!(key1.len(), key_length);
    
    // Create a different salt for overriding
    let different_salt = b"different_salt";
    
    // Derive with override parameters
    let key2 = pbkdf2.derive_key(password, Some(different_salt), None, 16).unwrap();
    assert_eq!(key2.len(), 16);
    assert_ne!(key1, key2);
}

/// Test PBKDF2 with invalid parameters
/// 
/// This test verifies error handling for invalid input parameters:
/// 1. Zero iterations
/// 2. Zero output length
#[test]
fn test_pbkdf2_invalid_parameters() {
    // Test with zero iterations
    let password = b"password";
    let salt = b"salt";
    let iterations = 0;
    let key_length = 32;
    
    let result = Pbkdf2::<Sha256>::pbkdf2(password, salt, iterations, key_length);
    assert!(result.is_err());
    
    // Test with zero output length
    let iterations = 1000;
    let key_length = 0;
    
    let result = Pbkdf2::<Sha256>::pbkdf2(password, salt, iterations, key_length);
    assert!(result.is_err());
}