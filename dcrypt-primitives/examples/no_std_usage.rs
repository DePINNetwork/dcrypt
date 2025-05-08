//! Simple no_std example for DCRYPT-Primitives
//!
//! This example shows how to use the library in a no_std environment.
//! To build this example with no_std support:
//!
//! ```
//! cargo build --example no_std_usage --no-default-features --features "alloc,hash,block"
//! ```

#![no_std]
#![allow(unused_variables, dead_code)]  // For example purposes

// For no_std environments that have alloc
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use dcrypt_primitives::hash::{HashFunction, Sha256};
use dcrypt_primitives::block::aes::Aes128;
use dcrypt_primitives::block::BlockCipher;
use dcrypt_primitives::error::Result;

/// Example function using hash functions in a no_std environment
#[cfg(feature = "hash")]
pub fn hash_data(data: &[u8]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(data)?;
    
    let hash = hasher.finalize()?;
    
    // Convert Vec<u8> to fixed-size array for no_std environments
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    
    Ok(result)
}

/// Example function using block ciphers in a no_std environment
#[cfg(feature = "block")]
pub fn encrypt_block(key: &[u8], data: &[u8]) -> Result<[u8; 16]> {
    let cipher = Aes128::new(key);
    
    // Prepare a block for encryption
    let mut block = [0u8; 16];
    block.copy_from_slice(&data[..16]);
    
    // Encrypt the block in place
    cipher.encrypt_block(&mut block)?;
    
    Ok(block)
}

/// Example function using AEAD with the alloc feature
#[cfg(all(feature = "aead", feature = "alloc"))]
pub fn encrypt_gcm(key: &[u8], nonce: &[u8], data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    use dcrypt_primitives::aead::Gcm;
    use dcrypt_primitives::block::AuthenticatedCipher;
    
    // Create AES-128-GCM instance
    let mut key_bytes = [0u8; 16];
    key_bytes.copy_from_slice(&key[..16]);
    
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce[..12]);
    
    let cipher = Aes128::new(&key_bytes);
    let gcm = Gcm::new(cipher, &nonce_bytes)?;
    
    // Encrypt the data with associated data if provided
    let ciphertext = gcm.encrypt(data, aad)?;
    
    Ok(ciphertext)
}

/// Example function that works in a minimal no_std environment without alloc
pub fn xor_encrypt(key: &[u8], data: &mut [u8]) {
    // Simple XOR encryption (for illustration purposes only)
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

// Minimal main function to satisfy the compiler
fn main() -> Result<()> {
    // Test data
    let key = [0x42; 16];
    let nonce = [0x24; 12];
    let mut data = [0x55; 16];
    
    // Basic XOR encryption (always available in no_std)
    xor_encrypt(&key, &mut data);
    
    // Use hash function if available
    #[cfg(feature = "hash")]
    {
        let hash = hash_data(&data)?;
        // In a real application, you'd use this hash
    }
    
    // Use block cipher if available
    #[cfg(feature = "block")]
    {
        let encrypted = encrypt_block(&key, &data)?;
        // In a real application, you'd use this encrypted data
    }
    
    // Use AEAD if available
    #[cfg(all(feature = "aead", feature = "alloc"))]
    {
        let ciphertext = encrypt_gcm(&key, &nonce, &data, None)?;
        // In a real application, you'd use this ciphertext
    }
    
    Ok(())
}