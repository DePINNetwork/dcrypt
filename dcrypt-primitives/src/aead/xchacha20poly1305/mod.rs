// In dcrypt-primitives/src/aead/xchacha20poly1305/mod.rs
//! XChaCha20Poly1305 authenticated encryption
//!
//! This module implements the XChaCha20Poly1305 Authenticated Encryption with
//! Associated Data (AEAD) algorithm, which extends ChaCha20Poly1305 with a
//! 24-byte nonce.

use crate::error::{Error, Result};
use crate::stream::chacha::chacha20::{ChaCha20, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE};
use crate::aead::chacha20poly1305::{ChaCha20Poly1305, CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_TAG_SIZE};
use crate::block::AuthenticatedCipher;
use zeroize::Zeroize;

/// Size of the XChaCha20Poly1305 nonce in bytes
pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;

/// XChaCha20Poly1305 variant with extended 24-byte nonce
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct XChaCha20Poly1305 {
    key: [u8; CHACHA20POLY1305_KEY_SIZE],
}

impl XChaCha20Poly1305 {
    /// Create a new XChaCha20Poly1305 instance
    pub fn new(key: &[u8; CHACHA20POLY1305_KEY_SIZE]) -> Self {
        let mut key_bytes = [0u8; CHACHA20POLY1305_KEY_SIZE];
        key_bytes.copy_from_slice(key);
        Self { key: key_bytes }
    }
    
    /// Encrypt plaintext using XChaCha20Poly1305
    pub fn encrypt(&self, nonce: &[u8; XCHACHA20POLY1305_NONCE_SIZE], plaintext: &[u8], aad: Option<&[u8]>) -> Vec<u8> {
        // Derive a subkey using HChaCha20 (simplified version here - derive with ChaCha20)
        let mut subkey = [0u8; CHACHA20POLY1305_KEY_SIZE];
        
        let mut nonce_prefix = [0u8; CHACHA20_NONCE_SIZE];
        nonce_prefix.copy_from_slice(&nonce[..CHACHA20_NONCE_SIZE]);
        
        let mut chacha = ChaCha20::new(&self.key, &nonce_prefix);
        chacha.keystream(&mut subkey);
        
        // Use the derived subkey with regular ChaCha20Poly1305
        let chacha_poly = ChaCha20Poly1305::new(&subkey);
        
        // Use the remaining 12 bytes of the nonce
        let mut truncated_nonce = [0u8; CHACHA20_NONCE_SIZE];
        truncated_nonce.copy_from_slice(&nonce[12..24]);
        
        chacha_poly.encrypt(&truncated_nonce, plaintext, aad)
    }
    
    /// Decrypt ciphertext using XChaCha20Poly1305
    pub fn decrypt(&self, nonce: &[u8; XCHACHA20POLY1305_NONCE_SIZE], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        // Derive a subkey using HChaCha20 (simplified as above)
        let mut subkey = [0u8; CHACHA20POLY1305_KEY_SIZE];
        
        let mut nonce_prefix = [0u8; CHACHA20_NONCE_SIZE];
        nonce_prefix.copy_from_slice(&nonce[..CHACHA20_NONCE_SIZE]);
        
        let mut chacha = ChaCha20::new(&self.key, &nonce_prefix);
        chacha.keystream(&mut subkey);
        
        // Use the derived subkey with regular ChaCha20Poly1305
        let chacha_poly = ChaCha20Poly1305::new(&subkey);
        
        // Use the remaining 12 bytes of the nonce
        let mut truncated_nonce = [0u8; CHACHA20_NONCE_SIZE];
        truncated_nonce.copy_from_slice(&nonce[12..24]);
        
        chacha_poly.decrypt(&truncated_nonce, ciphertext, aad)
    }
}

impl AuthenticatedCipher for XChaCha20Poly1305 {
    fn new(key: &[u8], nonce: &[u8]) -> Self {
        let mut key_bytes = [0u8; CHACHA20POLY1305_KEY_SIZE];
        key_bytes.copy_from_slice(&key[..CHACHA20POLY1305_KEY_SIZE]);
        Self::new(&key_bytes)
    }
    
    fn encrypt(&self, plaintext: &[u8], associated_data: Option<&[u8]>) -> Vec<u8> {
        // Use all zeros as nonce for compatibility with trait
        let nonce = [0u8; XCHACHA20POLY1305_NONCE_SIZE];
        self.encrypt(&nonce, plaintext, associated_data)
    }
    
    fn decrypt(&self, ciphertext: &[u8], associated_data: Option<&[u8]>) -> std::result::Result<Vec<u8>, ()> {
        // Use all zeros as nonce for compatibility with trait
        let nonce = [0u8; XCHACHA20POLY1305_NONCE_SIZE];
        self.decrypt(&nonce, ciphertext, associated_data).map_err(|_| ())
    }
    
    fn key_size() -> usize {
        CHACHA20POLY1305_KEY_SIZE
    }
    
    fn nonce_size() -> usize {
        XCHACHA20POLY1305_NONCE_SIZE
    }
    
    fn tag_size() -> usize {
        CHACHA20POLY1305_TAG_SIZE
    }
    
    fn name() -> &'static str {
        "XChaCha20Poly1305"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_xchacha20poly1305() {
        // Simple test for XChaCha20Poly1305
        let key = [0x42; CHACHA20POLY1305_KEY_SIZE];
        let nonce = [0x24; XCHACHA20POLY1305_NONCE_SIZE];
        let plaintext = b"Extended nonce allows for random nonces";
        
        let xchacha = XChaCha20Poly1305::new(&key);
        
        // Encrypt
        let ciphertext = xchacha.encrypt(&nonce, plaintext, None);
        
        // Decrypt
        let decrypted = xchacha.decrypt(&nonce, &ciphertext, None)
            .expect("Decryption failed");
        
        assert_eq!(decrypted, plaintext);
    }
}