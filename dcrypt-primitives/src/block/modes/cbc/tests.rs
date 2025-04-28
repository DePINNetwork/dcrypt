use super::*;
use crate::block::aes::{Aes128, Aes192, Aes256};
use hex;

#[test]
fn test_aes_cbc_nist_vectors() {
    // Path to the test vector files
    let base_path = env!("CARGO_MANIFEST_DIR");
    let vectors_dir = format!("{}/../dcrypt-test/src/vectors/cbc", base_path);
    
    // Path to the test vector files
    let aes128_encrypt_path = format!("{}/CBC-AES128-Encrypt.rsp", vectors_dir);
    let aes128_decrypt_path = format!("{}/CBC-AES128-Decrypt.rsp", vectors_dir);
    let aes192_encrypt_path = format!("{}/CBC-AES192-Encrypt.rsp", vectors_dir);
    let aes192_decrypt_path = format!("{}/CBC-AES192-Decrypt.rsp", vectors_dir);
    let aes256_encrypt_path = format!("{}/CBC-AES256-Encrypt.rsp", vectors_dir);
    let aes256_decrypt_path = format!("{}/CBC-AES256-Decrypt.rsp", vectors_dir);
    
    // Check if files exist and provide helpful message if they don't
    assert!(
        std::path::Path::new(&aes128_encrypt_path).exists(),
        "Test vector file not found: {}. Please ensure the test vectors are in the correct directory.",
        aes128_encrypt_path
    );
    
    // Run the tests
    run_aes128_cbc_tests(&aes128_encrypt_path, "AES-128 Encrypt", true);
    run_aes128_cbc_tests(&aes128_decrypt_path, "AES-128 Decrypt", false);
    run_aes192_cbc_tests(&aes192_encrypt_path, "AES-192 Encrypt", true);
    run_aes192_cbc_tests(&aes192_decrypt_path, "AES-192 Decrypt", false);
    run_aes256_cbc_tests(&aes256_encrypt_path, "AES-256 Encrypt", true);
    run_aes256_cbc_tests(&aes256_decrypt_path, "AES-256 Decrypt", false);
}

#[derive(Debug)]
struct AesCbcTestVector {
    count: usize,
    key: String,      // Hex-encoded key
    iv: String,       // Hex-encoded IV
    plaintext: String,  // Hex-encoded plaintext
    ciphertext: String, // Hex-encoded ciphertext
}

fn parse_aes_cbc_test_file(filepath: &str) -> Vec<AesCbcTestVector> {
    use std::fs::File;
    use std::path::Path;
    use std::io::{BufRead, BufReader};
    
    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let mut test_vectors = Vec::new();
    let mut current_vector: Option<AesCbcTestVector> = None;
    let mut is_encrypt_mode = false;
    
    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Detect test mode (encryption or decryption)
        if line == "[ENCRYPT]" {
            is_encrypt_mode = true;
            continue;
        } else if line == "[DECRYPT]" {
            is_encrypt_mode = false;
            continue;
        }
        
        if line.starts_with("COUNT = ") {
            // Start of a new test case
            if let Some(vector) = current_vector.take() {
                test_vectors.push(vector);
            }
            
            // Extract count
            let count = line[8..].parse::<usize>().unwrap();
            
            current_vector = Some(AesCbcTestVector {
                count,
                key: String::new(),
                iv: String::new(),
                plaintext: String::new(),
                ciphertext: String::new(),
            });
        } else if let Some(ref mut vector) = current_vector {
            // Parse test vector data
            if line.starts_with("KEY = ") {
                vector.key = line[6..].to_string();
            } else if line.starts_with("IV = ") {
                vector.iv = line[5..].to_string();
            } else if line.starts_with("PLAINTEXT = ") {
                vector.plaintext = line[12..].to_string();
            } else if line.starts_with("CIPHERTEXT = ") {
                vector.ciphertext = line[13..].to_string();
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
        let key = hex::decode(&test.key).unwrap_or_else(|_| 
            panic!("Invalid hex key in test vector {}: {}", i, test.key));
        
        let iv = hex::decode(&test.iv).unwrap_or_else(|_| 
            panic!("Invalid hex IV in test vector {}: {}", i, test.iv));
        
        // Ensure key has the expected size for AES-128
        assert_eq!(key.len(), 16, 
            "Key size mismatch for {} test case {}. Expected: 16, Got: {}",
            name, i, key.len());
        
        // Create AES-128 cipher and CBC mode
        let cipher = Aes128::new(&key);
        let cbc = Cbc::new(cipher, &iv);
        
        if is_encrypt {
            // Test encryption
            let plaintext = hex::decode(&test.plaintext).unwrap_or_else(|_| 
                panic!("Invalid hex plaintext in test vector {}: {}", i, test.plaintext));
            
            let expected = hex::decode(&test.ciphertext).unwrap_or_else(|_| 
                panic!("Invalid hex ciphertext in test vector {}: {}", i, test.ciphertext));
            
            let result = cbc.encrypt(&plaintext);
            
            assert_eq!(result, expected, 
                "{} test case {} failed.\nInput: {}\nExpected: {}\nGot: {}", 
                name, i, test.plaintext, test.ciphertext, hex::encode(&result));
        } else {
            // Test decryption
            let ciphertext = hex::decode(&test.ciphertext).unwrap_or_else(|_| 
                panic!("Invalid hex ciphertext in test vector {}: {}", i, test.ciphertext));
            
            let expected = hex::decode(&test.plaintext).unwrap_or_else(|_| 
                panic!("Invalid hex plaintext in test vector {}: {}", i, test.plaintext));
            
            let result = cbc.decrypt(&ciphertext);
            
            assert_eq!(result, expected, 
                "{} test case {} failed.\nInput: {}\nExpected: {}\nGot: {}", 
                name, i, test.ciphertext, test.plaintext, hex::encode(&result));
        }
    }
}

// Test function for AES-192
fn run_aes192_cbc_tests(filepath: &str, name: &str, is_encrypt: bool) {
    let test_vectors = parse_aes_cbc_test_file(filepath);
    
    for (i, test) in test_vectors.iter().enumerate() {
        // Convert hex strings to bytes
        let key = hex::decode(&test.key).unwrap_or_else(|_| 
            panic!("Invalid hex key in test vector {}: {}", i, test.key));
        
        let iv = hex::decode(&test.iv).unwrap_or_else(|_| 
            panic!("Invalid hex IV in test vector {}: {}", i, test.iv));
        
        // Ensure key has the expected size for AES-192
        assert_eq!(key.len(), 24, 
            "Key size mismatch for {} test case {}. Expected: 24, Got: {}",
            name, i, key.len());
        
        // Create AES-192 cipher and CBC mode
        let cipher = Aes192::new(&key);
        let cbc = Cbc::new(cipher, &iv);
        
        if is_encrypt {
            // Test encryption
            let plaintext = hex::decode(&test.plaintext).unwrap_or_else(|_| 
                panic!("Invalid hex plaintext in test vector {}: {}", i, test.plaintext));
            
            let expected = hex::decode(&test.ciphertext).unwrap_or_else(|_| 
                panic!("Invalid hex ciphertext in test vector {}: {}", i, test.ciphertext));
            
            let result = cbc.encrypt(&plaintext);
            
            assert_eq!(result, expected, 
                "{} test case {} failed.\nInput: {}\nExpected: {}\nGot: {}", 
                name, i, test.plaintext, test.ciphertext, hex::encode(&result));
        } else {
            // Test decryption
            let ciphertext = hex::decode(&test.ciphertext).unwrap_or_else(|_| 
                panic!("Invalid hex ciphertext in test vector {}: {}", i, test.ciphertext));
            
            let expected = hex::decode(&test.plaintext).unwrap_or_else(|_| 
                panic!("Invalid hex plaintext in test vector {}: {}", i, test.plaintext));
            
            let result = cbc.decrypt(&ciphertext);
            
            assert_eq!(result, expected, 
                "{} test case {} failed.\nInput: {}\nExpected: {}\nGot: {}", 
                name, i, test.ciphertext, test.plaintext, hex::encode(&result));
        }
    }
}

// Test function for AES-256
fn run_aes256_cbc_tests(filepath: &str, name: &str, is_encrypt: bool) {
    let test_vectors = parse_aes_cbc_test_file(filepath);
    
    for (i, test) in test_vectors.iter().enumerate() {
        // Convert hex strings to bytes
        let key = hex::decode(&test.key).unwrap_or_else(|_| 
            panic!("Invalid hex key in test vector {}: {}", i, test.key));
        
        let iv = hex::decode(&test.iv).unwrap_or_else(|_| 
            panic!("Invalid hex IV in test vector {}: {}", i, test.iv));
        
        // Ensure key has the expected size for AES-256
        assert_eq!(key.len(), 32, 
            "Key size mismatch for {} test case {}. Expected: 32, Got: {}",
            name, i, key.len());
        
        // Create AES-256 cipher and CBC mode
        let cipher = Aes256::new(&key);
        let cbc = Cbc::new(cipher, &iv);
        
        if is_encrypt {
            // Test encryption
            let plaintext = hex::decode(&test.plaintext).unwrap_or_else(|_| 
                panic!("Invalid hex plaintext in test vector {}: {}", i, test.plaintext));
            
            let expected = hex::decode(&test.ciphertext).unwrap_or_else(|_| 
                panic!("Invalid hex ciphertext in test vector {}: {}", i, test.ciphertext));
            
            let result = cbc.encrypt(&plaintext);
            
            assert_eq!(result, expected, 
                "{} test case {} failed.\nInput: {}\nExpected: {}\nGot: {}", 
                name, i, test.plaintext, test.ciphertext, hex::encode(&result));
        } else {
            // Test decryption
            let ciphertext = hex::decode(&test.ciphertext).unwrap_or_else(|_| 
                panic!("Invalid hex ciphertext in test vector {}: {}", i, test.ciphertext));
            
            let expected = hex::decode(&test.plaintext).unwrap_or_else(|_| 
                panic!("Invalid hex plaintext in test vector {}: {}", i, test.plaintext));
            
            let result = cbc.decrypt(&ciphertext);
            
            assert_eq!(result, expected, 
                "{} test case {} failed.\nInput: {}\nExpected: {}\nGot: {}", 
                name, i, test.ciphertext, test.plaintext, hex::encode(&result));
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
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
    let expected_ciphertext = hex::decode("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7").unwrap();
    
    let cipher = Aes128::new(&key);
    let cbc = Cbc::new(cipher, &iv);
    
    let ciphertext = cbc.encrypt(&plaintext);
    assert_eq!(ciphertext, expected_ciphertext);
    
    // Test decryption
    let cipher = Aes128::new(&key);
    let cbc = Cbc::new(cipher, &iv);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_cbc_multiple_blocks() {
    let key = [0x42; 16]; // 16-byte key for AES-128
    let iv = [0x24; 16];  // 16-byte IV
    
    // Generate a three-block plaintext
    let plaintext = vec![0xAA; 48]; // 3 blocks of 16 bytes
    
    let cipher = Aes128::new(&key);
    let cbc = Cbc::new(cipher, &iv);
    
    let ciphertext = cbc.encrypt(&plaintext);
    
    // Ensure the ciphertext is the same length as the plaintext
    assert_eq!(ciphertext.len(), plaintext.len());
    
    // Ensure the ciphertext is different from plaintext
    assert_ne!(ciphertext, plaintext);
    
    // Decrypt and verify
    let cipher = Aes128::new(&key);
    let cbc = Cbc::new(cipher, &iv);
    let decrypted = cbc.decrypt(&ciphertext);
    
    assert_eq!(decrypted, plaintext);
}