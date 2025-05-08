//! ChaCha20Poly1305 authenticated encryption
//!
//! This module provides an implementation of the ChaCha20Poly1305 authenticated encryption
//! algorithm as defined in RFC 8439.

use crate::error::{Error, Result};
use dcrypt_primitives::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt_primitives::aead::xchacha20poly1305::XChaCha20Poly1305;
use dcrypt_primitives::aead::chacha20poly1305::CHACHA20POLY1305_TAG_SIZE;
use rand::RngCore;
use super::common::{ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, ChaCha20Poly1305CiphertextPackage};
use crate::cipher::{SymmetricCipher, Aead};

/// ChaCha20Poly1305 authenticated encryption
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
    pub(crate) key: ChaCha20Poly1305Key,
}

impl SymmetricCipher for ChaCha20Poly1305Cipher {
    type Key = ChaCha20Poly1305Key;
    
    fn new(key: &Self::Key) -> Result<Self> {
        // Unlike AES-GCM, the ChaCha20Poly1305 constructor doesn't return a Result
        // but we still wrap it in Ok() for consistency with the new trait design
        let cipher = ChaCha20Poly1305::new(key.as_bytes());
        Ok(Self { 
            cipher,
            key: key.clone(),
        })
    }
    
    fn name() -> &'static str {
        "ChaCha20Poly1305"
    }
}

impl Aead for ChaCha20Poly1305Cipher {
    type Nonce = ChaCha20Poly1305Nonce;
    
    fn encrypt(&self, nonce: &Self::Nonce, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        // With thiserror's From implementation, we can use ? directly
        Ok(self.cipher.encrypt(nonce.as_bytes(), plaintext, aad)?)
    }
    
    fn decrypt(&self, nonce: &Self::Nonce, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        // With thiserror's From implementation, we can use ? directly
        Ok(self.cipher.decrypt(nonce.as_bytes(), ciphertext, aad)?)
    }
    
    fn generate_nonce() -> Self::Nonce {
        ChaCha20Poly1305Nonce::generate()
    }
}

impl ChaCha20Poly1305Cipher {
    /// Generates a new ChaCha20Poly1305 instance with a random key
    pub fn generate() -> Result<(Self, ChaCha20Poly1305Key)> {
        let key = ChaCha20Poly1305Key::generate();
        let cipher = Self::new(&key)?;
        Ok((cipher, key))
    }
    
    /// Convenience method for encryption with a new random nonce
    pub fn encrypt_with_random_nonce(&self, plaintext: &[u8], aad: Option<&[u8]>) 
        -> Result<(Vec<u8>, ChaCha20Poly1305Nonce)> 
    {
        let nonce = Self::generate_nonce();
        let ciphertext = self.encrypt(&nonce, plaintext, aad)?;
        Ok((ciphertext, nonce))
    }
    
    /// Helper method to decrypt and verify all in one step
    pub fn decrypt_and_verify(&self, ciphertext: &[u8], nonce: &ChaCha20Poly1305Nonce, aad: Option<&[u8]>) 
        -> Result<Vec<u8>> 
    {
        self.decrypt(nonce, ciphertext, aad)
    }
    
    /// Returns the key used by this instance
    pub fn key(&self) -> &ChaCha20Poly1305Key {
        &self.key
    }
    
    /// Encrypts data and returns a package containing both nonce and ciphertext
    pub fn encrypt_to_package(&self, plaintext: &[u8], aad: Option<&[u8]>) 
        -> Result<ChaCha20Poly1305CiphertextPackage> 
    {
        let (ciphertext, nonce) = self.encrypt_with_random_nonce(plaintext, aad)?;
        Ok(ChaCha20Poly1305CiphertextPackage::new(nonce, ciphertext))
    }
    
    /// Decrypts a package containing both nonce and ciphertext
    pub fn decrypt_package(&self, package: &ChaCha20Poly1305CiphertextPackage, aad: Option<&[u8]>) 
        -> Result<Vec<u8>> 
    {
        self.decrypt(&package.nonce, &package.ciphertext, aad)
    }
}

/// XChaCha20Poly1305 authenticated encryption with extended 24-byte nonce
pub struct XChaCha20Poly1305Cipher {
    cipher: XChaCha20Poly1305,
    pub(crate) key: ChaCha20Poly1305Key,
}

impl SymmetricCipher for XChaCha20Poly1305Cipher {
    type Key = ChaCha20Poly1305Key;
    
    fn new(key: &Self::Key) -> Result<Self> {
        // Unlike AES-GCM, the XChaCha20Poly1305 constructor doesn't return a Result
        // but we still wrap it in Ok() for consistency with the new trait design
        let cipher = XChaCha20Poly1305::new(key.as_bytes());
        Ok(Self { 
            cipher,
            key: key.clone(),
        })
    }
    
    fn name() -> &'static str {
        "XChaCha20Poly1305"
    }
}

/// Extended 24-byte nonce for XChaCha20Poly1305
#[derive(Clone, Debug)]
pub struct XChaCha20Poly1305Nonce([u8; 24]);

impl XChaCha20Poly1305Nonce {
    /// Creates a new nonce from raw bytes
    pub fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }
    
    /// Creates a new random nonce
    pub fn generate() -> Self {
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self(nonce)
    }
    
    /// Returns a reference to the raw nonce bytes
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
    
    /// Serializes the nonce to a base64 string
    pub fn to_string(&self) -> String {
        base64::encode(&self.0)
    }
    
    /// Creates a nonce from a base64 string
    pub fn from_string(s: &str) -> Result<Self> {
        let bytes = base64::decode(s)
            .map_err(|_| Error::InvalidFormat)?;
            
        if bytes.len() != 24 {
            return Err(Error::InvalidFormat);
        }
        
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes);
        
        Ok(Self(nonce))
    }
}

impl Aead for XChaCha20Poly1305Cipher {
    type Nonce = XChaCha20Poly1305Nonce;
    
    fn encrypt(&self, nonce: &Self::Nonce, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        // With thiserror's From implementation, we can use ? directly
        Ok(self.cipher.encrypt(nonce.as_bytes(), plaintext, aad)?)
    }
    
    fn decrypt(&self, nonce: &Self::Nonce, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        // With thiserror's From implementation, we can use ? directly
        Ok(self.cipher.decrypt(nonce.as_bytes(), ciphertext, aad)?)
    }
    
    fn generate_nonce() -> Self::Nonce {
        XChaCha20Poly1305Nonce::generate()
    }
}

impl XChaCha20Poly1305Cipher {
    /// Generates a new XChaCha20Poly1305 instance with a random key
    pub fn generate() -> Result<(Self, ChaCha20Poly1305Key)> {
        let key = ChaCha20Poly1305Key::generate();
        let cipher = Self::new(&key)?;
        Ok((cipher, key))
    }
    
    /// Convenience method for encryption with a new random nonce
    pub fn encrypt_with_random_nonce(&self, plaintext: &[u8], aad: Option<&[u8]>) 
        -> Result<(Vec<u8>, XChaCha20Poly1305Nonce)> 
    {
        let nonce = Self::generate_nonce();
        let ciphertext = self.encrypt(&nonce, plaintext, aad)?;
        Ok((ciphertext, nonce))
    }
    
    /// Helper method to decrypt and verify all in one step
    pub fn decrypt_and_verify(&self, ciphertext: &[u8], nonce: &XChaCha20Poly1305Nonce, aad: Option<&[u8]>) 
        -> Result<Vec<u8>> 
    {
        self.decrypt(nonce, ciphertext, aad)
    }
}