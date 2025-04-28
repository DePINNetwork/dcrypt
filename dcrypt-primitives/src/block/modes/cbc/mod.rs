//! Cipher Block Chaining (CBC) mode of operation for block ciphers
//!
//! CBC mode encrypts each block of plaintext by XORing it with the previous
//! ciphertext block before applying the cipher. The first block is XORed with
//! an initialization vector (IV).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use zeroize::Zeroize;

use super::super::BlockCipher;

/// CBC mode implementation
#[derive(Clone, Zeroize)]
pub struct Cbc<B: BlockCipher> {
    cipher: B,
    iv: Vec<u8>,
}

impl<B: BlockCipher> Cbc<B> {
    /// Creates a new CBC mode instance with the given cipher and IV
    pub fn new(cipher: B, iv: &[u8]) -> Self {
        assert_eq!(iv.len(), B::BLOCK_SIZE, "IV must be the same size as the cipher block size");
        
        Self {
            cipher,
            iv: iv.to_vec(),
        }
    }
    
    /// Encrypts a message using CBC mode
    ///
    /// The plaintext must be a multiple of the block size.
    /// For plaintext that is not a multiple of the block size,
    /// padding must be applied before calling this function.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(plaintext.len() % B::BLOCK_SIZE, 0, "Plaintext length must be a multiple of the block size");
        
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut prev_block = self.iv.clone();
        
        // Process the plaintext in blocks
        for chunk in plaintext.chunks(B::BLOCK_SIZE) {
            let mut block = [0u8; 16]; // AES block size is 16 bytes
            block[..chunk.len()].copy_from_slice(chunk);
            
            // XOR with previous ciphertext block (or IV for the first block)
            for i in 0..B::BLOCK_SIZE {
                block[i] ^= prev_block[i];
            }
            
            // Encrypt the XORed block
            self.cipher.encrypt_block(&mut block);
            
            // Append to ciphertext and update previous block
            ciphertext.extend_from_slice(&block);
            prev_block = block.to_vec();
        }
        
        ciphertext
    }
    
    /// Decrypts a message using CBC mode
    ///
    /// The ciphertext must be a multiple of the block size.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        assert_eq!(ciphertext.len() % B::BLOCK_SIZE, 0, "Ciphertext length must be a multiple of the block size");
        
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut prev_block = self.iv.clone();
        
        // Process the ciphertext in blocks
        for chunk in ciphertext.chunks(B::BLOCK_SIZE) {
            let mut block = [0u8; 16]; // AES block size is 16 bytes
            block[..chunk.len()].copy_from_slice(chunk);
            
            // Save current ciphertext block
            let current_block = block.clone();
            
            // Decrypt the block
            self.cipher.decrypt_block(&mut block);
            
            // XOR with previous ciphertext block (or IV for the first block)
            for i in 0..B::BLOCK_SIZE {
                block[i] ^= prev_block[i];
            }
            
            // Append to plaintext and update previous block
            plaintext.extend_from_slice(&block);
            prev_block = current_block.to_vec();
        }
        
        plaintext
    }
}

#[cfg(test)]
mod tests;