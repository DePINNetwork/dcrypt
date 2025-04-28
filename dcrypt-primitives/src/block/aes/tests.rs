use super::*;
use hex;

#[test]
fn test_aes128_encrypt() {
    // NIST test vector: AES-128-ECB
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    // Ciphertext: 3ad77bb40d7a3660a89ecaf32466ef97
    
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let mut block = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let expected = hex::decode("3ad77bb40d7a3660a89ecaf32466ef97").unwrap();
    
    let aes = Aes128::new(&key);
    aes.encrypt_block(&mut block);
    
    assert_eq!(block, expected);
}

#[test]
fn test_aes128_decrypt() {
    // NIST test vector: AES-128-ECB
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // Ciphertext: 3ad77bb40d7a3660a89ecaf32466ef97
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let mut block = hex::decode("3ad77bb40d7a3660a89ecaf32466ef97").unwrap();
    let expected = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    
    let aes = Aes128::new(&key);
    aes.decrypt_block(&mut block);
    
    assert_eq!(block, expected);
}

#[test]
fn test_aes192_encrypt() {
    // NIST test vector: AES-192-ECB
    // Key: 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    // Ciphertext: bd334f1d6e45f25ff712a214571fa5cc
    
    let key = hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
    let mut block = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let expected = hex::decode("bd334f1d6e45f25ff712a214571fa5cc").unwrap();
    
    let aes = Aes192::new(&key);
    aes.encrypt_block(&mut block);
    
    assert_eq!(block, expected);
}

#[test]
fn test_aes192_decrypt() {
    // NIST test vector: AES-192-ECB
    // Key: 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    // Ciphertext: bd334f1d6e45f25ff712a214571fa5cc
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    
    let key = hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
    let mut block = hex::decode("bd334f1d6e45f25ff712a214571fa5cc").unwrap();
    let expected = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    
    let aes = Aes192::new(&key);
    aes.decrypt_block(&mut block);
    
    assert_eq!(block, expected);
}

#[test]
fn test_aes256_encrypt() {
    // NIST test vector: AES-256-ECB
    // Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    // Ciphertext: f3eed1bdb5d2a03c064b5a7e3db181f8
    
    let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
    let mut block = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let expected = hex::decode("f3eed1bdb5d2a03c064b5a7e3db181f8").unwrap();
    
    let aes = Aes256::new(&key);
    aes.encrypt_block(&mut block);
    
    assert_eq!(block, expected);
}

#[test]
fn test_aes256_decrypt() {
    // NIST test vector: AES-256-ECB
    // Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    // Ciphertext: f3eed1bdb5d2a03c064b5a7e3db181f8
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    
    let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
    let mut block = hex::decode("f3eed1bdb5d2a03c064b5a7e3db181f8").unwrap();
    let expected = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    
    let aes = Aes256::new(&key);
    aes.decrypt_block(&mut block);
    
    assert_eq!(block, expected);
}