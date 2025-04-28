//! AES-GCM authenticated encryption
//!
//! This module provides an implementation of the AES-GCM authenticated encryption
//! algorithm as defined in NIST SP 800-38D.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::error::{Error, Result};
use dcrypt_primitives::block::aes::{Aes128, Aes256};
use dcrypt_primitives::aead::Gcm;
use dcrypt_primitives::block::AuthenticatedCipher;
use dcrypt_primitives::BlockCipher;

use crate::aes::keys::{Aes128Key, Aes256Key};
use crate::cipher::{SymmetricCipher, Aead};

pub mod types;
pub mod aes128;
pub mod aes256;

// Re-export GCM-specific types
pub use types::{GcmNonce, AesCiphertextPackage};

// Define the struct here, before importing from aes128 and aes256
/// AES-GCM authenticated encryption
pub struct AesGcm<A: AuthenticatedCipher, K> {
    cipher: A,
    pub(crate) key: K, // Make key accessible to impl methods
}

/// AES-128-GCM implementation
pub type Aes128Gcm = AesGcm<Gcm<Aes128>, Aes128Key>;

/// AES-256-GCM implementation
pub type Aes256Gcm = AesGcm<Gcm<Aes256>, Aes256Key>;

// Now re-export the implementation functions from the sub-modules
pub use aes128::{
    Aes128GcmEncryptStream, 
    Aes128GcmDecryptStream,
    aes128_encrypt, 
    aes128_decrypt,
    aes128_encrypt_package, 
    aes128_decrypt_package
};

pub use aes256::{
    Aes256GcmEncryptStream, 
    Aes256GcmDecryptStream,
    aes256_encrypt, 
    aes256_decrypt,
    aes256_encrypt_package, 
    aes256_decrypt_package
};

// Implementation for Aes128Gcm
impl SymmetricCipher for Aes128Gcm {
    type Key = Aes128Key;
    
    fn new(key: &Self::Key) -> Self {
        let aes = Aes128::new(key.as_bytes());
        let gcm = Gcm::new(aes, &[0; 12]).expect("Failed to create GCM cipher");
        Self { 
            cipher: gcm,
            key: key.clone(),
        }
    }
    
    fn name() -> &'static str {
        "AES-128-GCM"
    }
}

impl Aead for Aes128Gcm {
    type Nonce = GcmNonce;
    
    fn encrypt(&self, nonce: &Self::Nonce, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let aes = Aes128::new(self.key.as_bytes());
        let gcm = Gcm::new(aes, nonce.as_bytes())
            .map_err(|_| Error::CryptoError("Failed to initialize GCM"))?;
        
        Ok(gcm.encrypt(plaintext, aad))
    }
    
    fn decrypt(&self, nonce: &Self::Nonce, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let aes = Aes128::new(self.key.as_bytes());
        let gcm = Gcm::new(aes, nonce.as_bytes())
            .map_err(|_| Error::CryptoError("Failed to initialize GCM"))?;
        
        gcm.decrypt(ciphertext, aad)
            .map_err(|_| Error::AuthenticationError)
    }
    
    fn generate_nonce() -> Self::Nonce {
        GcmNonce::generate()
    }
}

// Implementation for Aes256Gcm
impl SymmetricCipher for Aes256Gcm {
    type Key = Aes256Key;
    
    fn new(key: &Self::Key) -> Self {
        let aes = Aes256::new(key.as_bytes());
        let gcm = Gcm::new(aes, &[0; 12]).expect("Failed to create GCM cipher");
        Self { 
            cipher: gcm,
            key: key.clone(),
        }
    }
    
    fn name() -> &'static str {
        "AES-256-GCM"
    }
}

impl Aead for Aes256Gcm {
    type Nonce = GcmNonce;
    
    fn encrypt(&self, nonce: &Self::Nonce, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let aes = Aes256::new(self.key.as_bytes());
        let gcm = Gcm::new(aes, nonce.as_bytes())
            .map_err(|_| Error::CryptoError("Failed to initialize GCM"))?;
        
        Ok(gcm.encrypt(plaintext, aad))
    }
    
    fn decrypt(&self, nonce: &Self::Nonce, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let aes = Aes256::new(self.key.as_bytes());
        let gcm = Gcm::new(aes, nonce.as_bytes())
            .map_err(|_| Error::CryptoError("Failed to initialize GCM"))?;
        
        gcm.decrypt(ciphertext, aad)
            .map_err(|_| Error::AuthenticationError)
    }
    
    fn generate_nonce() -> Self::Nonce {
        GcmNonce::generate()
    }
}