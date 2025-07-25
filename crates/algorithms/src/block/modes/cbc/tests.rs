use super::*;
use crate::block::aes::{Aes128, Aes192, Aes256};
use crate::types::Nonce;
use crate::types::SecretBytes;
use hex;
use std::path::{Path, PathBuf};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..") // up to crates/
        .join("..") // up to workspace root
        .join("tests")
        .join("src")
        .join("vectors")
        .join("legacy_rsp")
        .join("cbc")
}

#[test]
fn test_aes_cbc_nist_vectors() {
    let dir = vectors_dir();

    // Path to the test vector files
    let aes128_encrypt = dir.join("CBC-AES128-Encrypt.rsp");
    let aes128_decrypt = dir.join("CBC-AES128-Decrypt.rsp");
    let aes192_encrypt = dir.join("CBC-AES192-Encrypt.rsp");
    let aes192_decrypt = dir.join("CBC-AES192-Decrypt.rsp");
    let aes256_encrypt = dir.join("CBC-AES256-Encrypt.rsp");
    let aes256_decrypt = dir.join("CBC-AES256-Decrypt.rsp");

    // Check if files exist and provide helpful message if they don't
    for path in [
        &aes128_encrypt,
        &aes128_decrypt,
        &aes192_encrypt,
        &aes192_decrypt,
        &aes256_encrypt,
        &aes256_decrypt,
    ] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }

    // Run the tests
    run_aes128_cbc_tests(aes128_encrypt.to_str().unwrap(), "AES-128 Encrypt", true);
    run_aes128_cbc_tests(aes128_decrypt.to_str().unwrap(), "AES-128 Decrypt", false);
    run_aes192_cbc_tests(aes192_encrypt.to_str().unwrap(), "AES-192 Encrypt", true);
    run_aes192_cbc_tests(aes192_decrypt.to_str().unwrap(), "AES-192 Decrypt", false);
    run_aes256_cbc_tests(aes256_encrypt.to_str().unwrap(), "AES-256 Encrypt", true);
    run_aes256_cbc_tests(aes256_decrypt.to_str().unwrap(), "AES-256 Decrypt", false);
}

#[derive(Debug)]
struct AesCbcTestVector {
    count: usize,
    key: String,        // Hex-encoded key
    iv: String,         // Hex-encoded IV
    plaintext: String,  // Hex-encoded plaintext
    ciphertext: String, // Hex-encoded ciphertext
}

fn parse_aes_cbc_test_file(filepath: &str) -> Vec<AesCbcTestVector> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut test_vectors = Vec::new();
    let mut current_vector: Option<AesCbcTestVector> = None;
    let mut _is_encrypt_mode = false;

    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Detect test mode (encryption or decryption)
        if line == "[ENCRYPT]" {
            _is_encrypt_mode = true;
            continue;
        } else if line == "[DECRYPT]" {
            _is_encrypt_mode = false;
            continue;
        }

        if let Some(count_str) = line.strip_prefix("COUNT = ") {
            // Start of a new test case
            if let Some(vector) = current_vector.take() {
                test_vectors.push(vector);
            }

            // Extract count
            let count = count_str.parse::<usize>().unwrap();

            current_vector = Some(AesCbcTestVector {
                count,
                key: String::new(),
                iv: String::new(),
                plaintext: String::new(),
                ciphertext: String::new(),
            });
        } else if let Some(ref mut vector) = current_vector {
            // Parse test vector data
            if let Some(key_str) = line.strip_prefix("KEY = ") {
                vector.key = key_str.to_string();
            } else if let Some(iv_str) = line.strip_prefix("IV = ") {
                vector.iv = iv_str.to_string();
            } else if let Some(plaintext_str) = line.strip_prefix("PLAINTEXT = ") {
                vector.plaintext = plaintext_str.to_string();
            } else if let Some(ciphertext_str) = line.strip_prefix("CIPHERTEXT = ") {
                vector.ciphertext = ciphertext_str.to_string();
            }
        }
    }

    // Add the last test vector if present
    if let Some(vector) = current_vector {
        test_vectors.push(vector);
    }

    test_vectors
}

// Test function for AES-128
fn run_aes128_cbc_tests(filepath: &str, name: &str, is_encrypt: bool) {
    let test_vectors = parse_aes_cbc_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Convert hex strings to bytes
        let key = hex::decode(&test.key)
            .unwrap_or_else(|_| panic!("Invalid hex key in test vector {}: {}", i, test.key));

        let iv_bytes = hex::decode(&test.iv)
            .unwrap_or_else(|_| panic!("Invalid hex IV in test vector {}: {}", i, test.iv));

        // Convert iv_bytes to Nonce<16>
        let mut iv_array = [0u8; 16];
        iv_array.copy_from_slice(&iv_bytes);
        let iv = Nonce::<16>::new(iv_array);

        // Ensure key has the expected size for AES-128
        assert_eq!(
            key.len(),
            16,
            "Key size mismatch for {} test case {} (COUNT={}). Expected: 16, Got: {}",
            name,
            i,
            test.count,
            key.len()
        );

        // Create AES-128 cipher and CBC mode
        let secret_key =
            SecretBytes::<16>::from_slice(&key).expect("Failed to create SecretBytes from key");
        let cipher = Aes128::new(&secret_key);
        let cbc = Cbc::new(cipher, &iv).unwrap();

        if is_encrypt {
            // Test encryption
            let plaintext = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let expected = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let result = cbc.encrypt(&plaintext).unwrap();

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.plaintext,
                test.ciphertext,
                hex::encode(&result)
            );
        } else {
            // Test decryption
            let ciphertext = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let expected = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let result = cbc.decrypt(&ciphertext).unwrap();

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.ciphertext,
                test.plaintext,
                hex::encode(&result)
            );
        }
    }
}

// Test function for AES-192
fn run_aes192_cbc_tests(filepath: &str, name: &str, is_encrypt: bool) {
    let test_vectors = parse_aes_cbc_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Convert hex strings to bytes
        let key = hex::decode(&test.key)
            .unwrap_or_else(|_| panic!("Invalid hex key in test vector {}: {}", i, test.key));

        let iv_bytes = hex::decode(&test.iv)
            .unwrap_or_else(|_| panic!("Invalid hex IV in test vector {}: {}", i, test.iv));

        // Convert iv_bytes to Nonce<16>
        let mut iv_array = [0u8; 16];
        iv_array.copy_from_slice(&iv_bytes);
        let iv = Nonce::<16>::new(iv_array);

        // Ensure key has the expected size for AES-192
        assert_eq!(
            key.len(),
            24,
            "Key size mismatch for {} test case {} (COUNT={}). Expected: 24, Got: {}",
            name,
            i,
            test.count,
            key.len()
        );

        // Create AES-192 cipher and CBC mode
        let secret_key =
            SecretBytes::<24>::from_slice(&key).expect("Failed to create SecretBytes from key");
        let cipher = Aes192::new(&secret_key);
        let cbc = Cbc::new(cipher, &iv).unwrap();

        if is_encrypt {
            // Test encryption
            let plaintext = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let expected = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let result = cbc.encrypt(&plaintext).unwrap();

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.plaintext,
                test.ciphertext,
                hex::encode(&result)
            );
        } else {
            // Test decryption
            let ciphertext = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let expected = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let result = cbc.decrypt(&ciphertext).unwrap();

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.ciphertext,
                test.plaintext,
                hex::encode(&result)
            );
        }
    }
}

// Test function for AES-256
fn run_aes256_cbc_tests(filepath: &str, name: &str, is_encrypt: bool) {
    let test_vectors = parse_aes_cbc_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Convert hex strings to bytes
        let key = hex::decode(&test.key)
            .unwrap_or_else(|_| panic!("Invalid hex key in test vector {}: {}", i, test.key));

        let iv_bytes = hex::decode(&test.iv)
            .unwrap_or_else(|_| panic!("Invalid hex IV in test vector {}: {}", i, test.iv));

        // Convert iv_bytes to Nonce<16>
        let mut iv_array = [0u8; 16];
        iv_array.copy_from_slice(&iv_bytes);
        let iv = Nonce::<16>::new(iv_array);

        // Ensure key has the expected size for AES-256
        assert_eq!(
            key.len(),
            32,
            "Key size mismatch for {} test case {} (COUNT={}). Expected: 32, Got: {}",
            name,
            i,
            test.count,
            key.len()
        );

        // Create AES-256 cipher and CBC mode
        let secret_key =
            SecretBytes::<32>::from_slice(&key).expect("Failed to create SecretBytes from key");
        let cipher = Aes256::new(&secret_key);
        let cbc = Cbc::new(cipher, &iv).unwrap();

        if is_encrypt {
            // Test encryption
            let plaintext = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let expected = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let result = cbc.encrypt(&plaintext).unwrap();

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.plaintext,
                test.ciphertext,
                hex::encode(&result)
            );
        } else {
            // Test decryption
            let ciphertext = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let expected = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let result = cbc.decrypt(&ciphertext).unwrap();

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.ciphertext,
                test.plaintext,
                hex::encode(&result)
            );
        }
    }
}

#[test]
fn test_aes_cbc() {
    // NIST SP 800-38A test vector F.2.1
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // IV: 000102030405060708090a0b0c0d0e0f
    // Plaintext: 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
    // Ciphertext: 7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7

    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv_bytes = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    // Convert iv_bytes to Nonce<16>
    let mut iv_array = [0u8; 16];
    iv_array.copy_from_slice(&iv_bytes);
    let iv = Nonce::<16>::new(iv_array);

    let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
    let expected_ciphertext = hex::decode("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7").unwrap();

    let secret_key =
        SecretBytes::<16>::from_slice(&key).expect("Failed to create SecretBytes from key");
    let cipher = Aes128::new(&secret_key);
    let cbc = Cbc::new(cipher, &iv).unwrap();

    let ciphertext = cbc.encrypt(&plaintext).unwrap();
    assert_eq!(ciphertext, expected_ciphertext);

    // Test decryption
    let secret_key =
        SecretBytes::<16>::from_slice(&key).expect("Failed to create SecretBytes from key");
    let cipher = Aes128::new(&secret_key);
    let cbc = Cbc::new(cipher, &iv).unwrap();
    let decrypted = cbc.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_cbc_multiple_blocks() {
    let key_array = [0x42; 16]; // 16-byte key for AES-128
    let iv_array = [0x24; 16]; // 16-byte IV
    let iv = Nonce::<16>::new(iv_array); // Create Nonce<16> from array

    // Generate a three-block plaintext
    let plaintext = vec![0xAA; 48]; // 3 blocks of 16 bytes

    let secret_key = SecretBytes::new(key_array);
    let cipher = Aes128::new(&secret_key);
    let cbc = Cbc::new(cipher, &iv).unwrap();

    let ciphertext = cbc.encrypt(&plaintext).unwrap();

    // Ensure the ciphertext is the same length as the plaintext
    assert_eq!(ciphertext.len(), plaintext.len());

    // Ensure the ciphertext is different from plaintext
    assert_ne!(ciphertext, plaintext);

    // Decrypt and verify
    let secret_key = SecretBytes::new(key_array);
    let cipher = Aes128::new(&secret_key);
    let cbc = Cbc::new(cipher, &iv).unwrap();
    let decrypted = cbc.decrypt(&ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}
