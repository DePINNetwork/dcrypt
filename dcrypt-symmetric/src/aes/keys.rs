//! Key types for AES-based ciphers

use zeroize::Zeroize;
use dcrypt_constants::utils::symmetric::{AES128_KEY_SIZE, AES256_KEY_SIZE};
use crate::error::{Error, Result};
use std::fmt;
use base64;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Sha256};
use rand::{RngCore, rngs::OsRng};

/// AES-128 key type
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Aes128Key([u8; AES128_KEY_SIZE]);

impl Aes128Key {
    /// Creates a new key from raw bytes
    pub fn new(bytes: [u8; AES128_KEY_SIZE]) -> Self {
        Self(bytes)
    }
    
    /// Creates a new random key
    pub fn generate() -> Self {
        let mut key = [0u8; AES128_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }
    
    /// Returns a reference to the raw key bytes
    pub fn as_bytes(&self) -> &[u8; AES128_KEY_SIZE] {
        &self.0
    }
    
    /// Securely serializes the key for storage
    pub fn to_secure_string(&self) -> String {
        let key_b64 = base64::encode(&self.0);
        format!("DCRYPT-AES128-KEY:{}", key_b64)
    }
    
    /// Loads a key from a secure serialized format
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        if !serialized.starts_with("DCRYPT-AES128-KEY:") {
            return Err(Error::InvalidFormat);
        }
        
        let b64_part = &serialized["DCRYPT-AES128-KEY:".len()..];
        let key_bytes = base64::decode(b64_part)
            .map_err(|_| Error::InvalidFormat)?;
            
        if key_bytes.len() != AES128_KEY_SIZE {
            return Err(Error::InvalidKeySize);
        }
        
        let mut key = [0u8; AES128_KEY_SIZE];
        key.copy_from_slice(&key_bytes);
        
        Ok(Self(key))
    }
}

impl fmt::Debug for Aes128Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aes128Key([REDACTED])")
    }
}

/// AES-256 key type
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Aes256Key([u8; AES256_KEY_SIZE]);

impl Aes256Key {
    /// Creates a new key from raw bytes
    pub fn new(bytes: [u8; AES256_KEY_SIZE]) -> Self {
        Self(bytes)
    }
    
    /// Creates a new random key
    pub fn generate() -> Self {
        let mut key = [0u8; AES256_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }
    
    /// Returns a reference to the raw key bytes
    pub fn as_bytes(&self) -> &[u8; AES256_KEY_SIZE] {
        &self.0
    }
    
    /// Securely serializes the key for storage
    pub fn to_secure_string(&self) -> String {
        let key_b64 = base64::encode(&self.0);
        format!("DCRYPT-AES256-KEY:{}", key_b64)
    }
    
    /// Loads a key from a secure serialized format
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        if !serialized.starts_with("DCRYPT-AES256-KEY:") {
            return Err(Error::InvalidFormat);
        }
        
        let b64_part = &serialized["DCRYPT-AES256-KEY:".len()..];
        let key_bytes = base64::decode(b64_part)
            .map_err(|_| Error::InvalidFormat)?;
            
        if key_bytes.len() != AES256_KEY_SIZE {
            return Err(Error::InvalidKeySize);
        }
        
        let mut key = [0u8; AES256_KEY_SIZE];
        key.copy_from_slice(&key_bytes);
        
        Ok(Self(key))
    }
}

impl fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aes256Key([REDACTED])")
    }
}

/// Derives an AES-128 key from a password and salt using PBKDF2-HMAC-SHA256
pub fn derive_aes128_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes128Key> {
    let mut key = [0u8; AES128_KEY_SIZE];
    
    // pbkdf2 returns () when successful, so we'll use a dummy result
    let _: () = pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut key);
    
    Ok(Aes128Key(key))
}

/// Derives an AES-256 key from a password and salt using PBKDF2-HMAC-SHA256
pub fn derive_aes256_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes256Key> {
    let mut key = [0u8; AES256_KEY_SIZE];
    
    // pbkdf2 returns () when successful, so we'll use a dummy result
    let _: () = pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut key);
    
    Ok(Aes256Key(key))
}

/// Generates a random salt for key derivation
pub fn generate_salt(size: usize) -> Vec<u8> {
    let mut salt = vec![0u8; size];
    OsRng.fill_bytes(&mut salt);
    salt
}