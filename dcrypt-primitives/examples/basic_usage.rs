// File: dcrypt-primitives/examples/basic_usage.rs

use dcrypt_primitives::hash::{HashFunction, Sha256, Sha3_256};
use dcrypt_primitives::xof::{ExtendableOutputFunction, ShakeXof256};
use dcrypt_primitives::block::aes::Aes128;
use dcrypt_primitives::block::modes::Ctr;
use dcrypt_primitives::aead::Gcm;  
use dcrypt_primitives::block::AuthenticatedCipher;
use dcrypt_primitives::BlockCipher;

fn main() {
    println!("DCRYPT Primitives Example");
    println!("========================\n");
    
    // Generate a random key for examples
    let key = [0x42; 16]; // 16-byte key for AES-128
    let nonce = [0x24; 12]; // 12-byte nonce
    
    // Sample message
    let message = b"Hello, DCRYPT! This is a test message to demonstrate the primitives.";
    
    // ===== Hash Functions =====
    println!("--- Hash Functions ---\n");
    
    // SHA-256
    let sha256_hash = Sha256::digest(message);
    println!("SHA-256: {}", hex::encode(&sha256_hash));
    
    // SHA3-256
    let sha3_hash = Sha3_256::digest(message);
    println!("SHA3-256: {}", hex::encode(&sha3_hash));
    
    // ===== Extendable Output Functions (XOFs) =====
    println!("\n--- Extendable Output Functions ---\n");
    
    // SHAKE-256 with different output lengths
    let shake_out_32 = ShakeXof256::generate(message, 32).unwrap();
    let shake_out_64 = ShakeXof256::generate(message, 64).unwrap();
    
    println!("SHAKE-256 (32 bytes): {}", hex::encode(&shake_out_32));
    println!("SHAKE-256 (64 bytes): {}", hex::encode(&shake_out_64));
    
    // ===== Block Cipher: Counter (CTR) Mode =====
    println!("\n--- CTR Mode Encryption ---\n");
    
    // Encrypt using AES-128-CTR
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::new(cipher, &nonce);
    
    let ctr_ciphertext = ctr.encrypt(message);
    println!("AES-128-CTR Ciphertext: {}", hex::encode(&ctr_ciphertext));
    
    // Decrypt using AES-128-CTR
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::new(cipher, &nonce);
    
    let ctr_plaintext = ctr.decrypt(&ctr_ciphertext);
    println!("AES-128-CTR Decrypted: {}", String::from_utf8_lossy(&ctr_plaintext));
    
    // ===== Block Cipher: Galois/Counter Mode (GCM) =====
    println!("\n--- GCM Authenticated Encryption ---\n");
    
    // Additional data to authenticate
    let aad = b"Additional authenticated data";
    
    // Encrypt and authenticate using AES-128-GCM
    let cipher = Aes128::new(&key);
    // Fix 1: Properly handle the Result from Gcm::new()
    let gcm = Gcm::new(cipher, &nonce).expect("Failed to create GCM cipher");
    
    let gcm_ciphertext = gcm.encrypt(message, Some(aad));
    println!("AES-128-GCM Ciphertext + Tag: {}", hex::encode(&gcm_ciphertext));
    
    // Decrypt and verify using AES-128-GCM
    let cipher = Aes128::new(&key);
    // Fix 2: Properly handle the Result from Gcm::new()
    let gcm = Gcm::new(cipher, &nonce).expect("Failed to create GCM cipher");
    
    match gcm.decrypt(&gcm_ciphertext, Some(aad)) {
        Ok(plaintext) => println!("AES-128-GCM Decrypted: {}", String::from_utf8_lossy(&plaintext)),
        Err(_) => println!("Authentication failed!"),
    }
    
    // Demonstrate authentication failure
    println!("\n--- GCM Authentication Failure ---\n");
    
    // Tamper with the ciphertext
    let mut tampered_ciphertext = gcm_ciphertext.clone();
    tampered_ciphertext[0] ^= 0x01; // Flip a bit
    
    let cipher = Aes128::new(&key);
    // Fix 3: Properly handle the Result from Gcm::new()
    let gcm = Gcm::new(cipher, &nonce).expect("Failed to create GCM cipher");
    
    match gcm.decrypt(&tampered_ciphertext, Some(aad)) {
        Ok(_) => println!("Authentication unexpectedly succeeded!"),
        Err(_) => println!("Authentication failed as expected!"),
    }
}