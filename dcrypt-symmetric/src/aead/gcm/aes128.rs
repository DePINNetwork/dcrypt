//! AES-128 cipher implementations

use crate::error::{Error, Result};
use crate::aes::keys::Aes128Key;
use super::types::{GcmNonce, AesCiphertextPackage};
use super::Aes128Gcm; // This now works because Aes128Gcm is defined in mod.rs
use crate::cipher::{SymmetricCipher, Aead};

impl Aes128Gcm {
    /// Generates a new AES-128-GCM instance with a random key
    pub fn generate() -> Result<(Self, Aes128Key)> {
        let key = Aes128Key::generate();
        let cipher = Self::new(&key)?;
        Ok((cipher, key))
    }
    
    /// Convenience method for encryption with a new random nonce
    pub fn encrypt_with_random_nonce(&self, plaintext: &[u8], aad: Option<&[u8]>) 
        -> Result<(Vec<u8>, GcmNonce)> 
    {
        let nonce = Self::generate_nonce();
        let ciphertext = self.encrypt(&nonce, plaintext, aad)?;
        Ok((ciphertext, nonce))
    }
    
    /// Helper method to decrypt and verify all in one step
    pub fn decrypt_and_verify(&self, ciphertext: &[u8], nonce: &GcmNonce, aad: Option<&[u8]>) 
        -> Result<Vec<u8>> 
    {
        self.decrypt(nonce, ciphertext, aad)
    }
    
    /// Returns the key used by this instance
    pub fn key(&self) -> &Aes128Key {
        &self.key
    }
    
    /// Encrypts data and returns a package containing both nonce and ciphertext
    pub fn encrypt_to_package(&self, plaintext: &[u8], aad: Option<&[u8]>) 
        -> Result<AesCiphertextPackage> 
    {
        let (ciphertext, nonce) = self.encrypt_with_random_nonce(plaintext, aad)?;
        Ok(AesCiphertextPackage::new(nonce, ciphertext))
    }
    
    /// Decrypts a package containing both nonce and ciphertext
    pub fn decrypt_package(&self, package: &AesCiphertextPackage, aad: Option<&[u8]>) 
        -> Result<Vec<u8>> 
    {
        self.decrypt(&package.nonce, &package.ciphertext, aad)
    }
}

// Additional standalone functions

/// Creates a new AES-128-GCM instance with a random key and encrypts data
pub fn aes128_encrypt(plaintext: &[u8], aad: Option<&[u8]>) 
    -> Result<(Vec<u8>, Aes128Key, GcmNonce)> 
{
    let key = Aes128Key::generate();
    let cipher = Aes128Gcm::new(&key)?;
    let nonce = Aes128Gcm::generate_nonce();
    
    let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;
    
    Ok((ciphertext, key, nonce))
}

/// Decrypts data using AES-128-GCM
pub fn aes128_decrypt(ciphertext: &[u8], key: &Aes128Key, nonce: &GcmNonce, aad: Option<&[u8]>) 
    -> Result<Vec<u8>> 
{
    let cipher = Aes128Gcm::new(key)?;
    cipher.decrypt(nonce, ciphertext, aad)
}

/// Encrypts data and returns a complete package with everything needed for decryption
pub fn aes128_encrypt_package(plaintext: &[u8], aad: Option<&[u8]>) 
    -> Result<(AesCiphertextPackage, Aes128Key)> 
{
    let key = Aes128Key::generate();
    let cipher = Aes128Gcm::new(&key)?;
    let package = cipher.encrypt_to_package(plaintext, aad)?;
    
    Ok((package, key))
}

/// Decrypts a package using the provided key
pub fn aes128_decrypt_package(package: &AesCiphertextPackage, key: &Aes128Key, aad: Option<&[u8]>) 
    -> Result<Vec<u8>> 
{
    let cipher = Aes128Gcm::new(key)?;
    cipher.decrypt_package(package, aad)
}