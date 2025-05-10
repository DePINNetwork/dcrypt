//! XChaCha20Poly1305 authenticated encryption with proper error handling
//!
//! This module implements the XChaCha20Poly1305 Authenticated Encryption with
//! Associated Data (AEAD) algorithm, which extends ChaCha20Poly1305 with a
//! 24-byte nonce.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use crate::error::{Error, Result, validate};
use crate::stream::chacha::chacha20::{ChaCha20, CHACHA20_NONCE_SIZE};
use crate::aead::chacha20poly1305::{
    ChaCha20Poly1305, CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_TAG_SIZE,
};
use crate::types::Nonce;
use crate::types::nonce::XChaCha20Compatible;
use dcrypt_core::traits::AuthenticatedCipher;
use zeroize::Zeroize;

/// Size of the XChaCha20Poly1305 nonce in bytes
pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;

/// XChaCha20Poly1305 variant with extended 24-byte nonce
#[derive(Clone, Zeroize)]
pub struct XChaCha20Poly1305 {
    key: [u8; CHACHA20POLY1305_KEY_SIZE],
}

// Manual implementation of Drop to ensure zeroization
impl Drop for XChaCha20Poly1305 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl XChaCha20Poly1305 {
    /// Create a new XChaCha20Poly1305 instance
    pub fn new(key: &[u8; CHACHA20POLY1305_KEY_SIZE]) -> Self {
        let mut key_bytes = [0u8; CHACHA20POLY1305_KEY_SIZE];
        key_bytes.copy_from_slice(key);
        Self { key: key_bytes }
    }
    
    /// Creates an instance from raw key bytes
    pub fn from_key(key: &[u8]) -> Result<Self> {
        validate::length(
            "XChaCha20Poly1305 key",
            key.len(),
            CHACHA20POLY1305_KEY_SIZE
        )?;
        
        let mut key_bytes = [0u8; CHACHA20POLY1305_KEY_SIZE];
        key_bytes.copy_from_slice(&key[..CHACHA20POLY1305_KEY_SIZE]);
        Ok(Self { key: key_bytes })
    }
    
    /// Encrypt plaintext using XChaCha20Poly1305
    pub fn encrypt<const N: usize>(
        &self,
        nonce: &Nonce<N>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> 
    where
        Nonce<N>: XChaCha20Compatible
    {
        // Derive a subkey using HChaCha20 (simplified via ChaCha20)
        let mut subkey = [0u8; CHACHA20POLY1305_KEY_SIZE];
        let mut nonce_prefix = [0u8; CHACHA20_NONCE_SIZE];
        
        // Get the nonce bytes from the generic Nonce type
        let nonce_bytes = nonce.as_ref();
        validate::length(
            "XChaCha20Poly1305 nonce",
            nonce_bytes.len(),
            XCHACHA20POLY1305_NONCE_SIZE
        )?;
        
        nonce_prefix.copy_from_slice(&nonce_bytes[..CHACHA20_NONCE_SIZE]);
        
        // Create a Nonce<12> object from the raw nonce bytes
        let nonce_obj = Nonce::<CHACHA20_NONCE_SIZE>::new(nonce_prefix);
        
        // Pass the Nonce object to ChaCha20::new
        let mut chacha = ChaCha20::new(&self.key, &nonce_obj);
        chacha.keystream(&mut subkey);

        // Use derived subkey with ChaCha20Poly1305
        let chacha_poly = ChaCha20Poly1305::new(&subkey);

        // Truncate nonce to 12 bytes
        let mut truncated_nonce = [0u8; CHACHA20_NONCE_SIZE];
        truncated_nonce.copy_from_slice(&nonce_bytes[12..24]);

        chacha_poly.encrypt_with_nonce(&truncated_nonce, plaintext, aad)
    }
    
    /// Decrypt ciphertext using XChaCha20Poly1305
    pub fn decrypt<const N: usize>(
        &self,
        nonce: &Nonce<N>,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> 
    where
        Nonce<N>: XChaCha20Compatible
    {
        // Derive subkey as above
        let mut subkey = [0u8; CHACHA20POLY1305_KEY_SIZE];
        let mut nonce_prefix = [0u8; CHACHA20_NONCE_SIZE];
        
        // Get the nonce bytes from the generic Nonce type
        let nonce_bytes = nonce.as_ref();
        validate::length(
            "XChaCha20Poly1305 nonce",
            nonce_bytes.len(),
            XCHACHA20POLY1305_NONCE_SIZE
        )?;
        
        nonce_prefix.copy_from_slice(&nonce_bytes[..CHACHA20_NONCE_SIZE]);
        
        // Create a Nonce<12> object from the raw nonce bytes
        let nonce_obj = Nonce::<CHACHA20_NONCE_SIZE>::new(nonce_prefix);
        
        // Pass the Nonce object to ChaCha20::new
        let mut chacha = ChaCha20::new(&self.key, &nonce_obj);
        chacha.keystream(&mut subkey);

        let chacha_poly = ChaCha20Poly1305::new(&subkey);

        let mut truncated_nonce = [0u8; CHACHA20_NONCE_SIZE];
        truncated_nonce.copy_from_slice(&nonce_bytes[12..24]);

        chacha_poly.decrypt_with_nonce(&truncated_nonce, ciphertext, aad)
    }
    
    /// Encrypt with a zero nonce (not recommended for general use)
    pub fn encrypt_with_zero_nonce(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let zero_nonce = Nonce::<XCHACHA20POLY1305_NONCE_SIZE>::zeroed();
        self.encrypt(&zero_nonce, plaintext, associated_data)
    }
    
    /// Decrypt with a zero nonce (not recommended for general use)
    pub fn decrypt_with_zero_nonce(
        &self,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let zero_nonce = Nonce::<XCHACHA20POLY1305_NONCE_SIZE>::zeroed();
        self.decrypt(&zero_nonce, ciphertext, associated_data)
    }
}

// Implement the marker trait AuthenticatedCipher correctly
impl AuthenticatedCipher for XChaCha20Poly1305 {
    const TAG_SIZE: usize = CHACHA20POLY1305_TAG_SIZE;
    const ALGORITHM_ID: &'static str = "XChaCha20Poly1305";
}

#[cfg(test)]
mod tests;