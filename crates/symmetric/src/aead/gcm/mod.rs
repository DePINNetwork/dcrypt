// File: crates/symmetric/src/aead/gcm/mod.rs
//! AES-GCM authenticated encryption
//!
//! This module provides an implementation of the AES-GCM authenticated encryption
//! algorithm as defined in NIST SP 800-38D.
//!
//! # Examples
//!
//! ```
//! use symmetric::{Aes128Gcm, GcmNonce}; // Corrected
//! use symmetric::Aes128Key;            // Corrected
//! use symmetric::{SymmetricCipher, Aead}; // Corrected
//! use symmetric::Result;                 // Corrected
//!
//! // Example function that handles errors properly
//! fn example() -> Result<()> {
//!     // Generate a random key
//!     let key = Aes128Key::generate();
//!
//!     // Create a cipher instance
//!     let cipher = Aes128Gcm::new(&key)?;
//!
//!     // Encrypt some data
//!     let plaintext = b"Secret message";
//!     let nonce = Aes128Gcm::generate_nonce();
//!     let ciphertext = cipher.encrypt(&nonce, plaintext, None)?;
//!
//!     // Decrypt the data
//!     let decrypted = cipher.decrypt(&nonce, &ciphertext, None)?;
//!     assert_eq!(decrypted, plaintext);
//!     Ok(())
//! }
//! ```
//!
//! ## Streaming Encryption
//!
/// For streaming encryption of large data, see the `streaming::gcm` module.
/// ```
/// use std::io::Cursor;
/// use symmetric::Aes128Key; // Corrected
/// use symmetric::streaming::{StreamingEncrypt, StreamingDecrypt}; // Corrected
/// use symmetric::streaming::gcm::{Aes128GcmEncryptStream, Aes128GcmDecryptStream}; // Corrected
/// use symmetric::Result; // Corrected
///
/// // Example function with proper error handling
/// fn example() -> Result<()> {
///     // Generate a random key
///     let key = Aes128Key::generate();
///
///     // Create an in-memory buffer for this example
///     let mut encrypted = Vec::new();
///
///     // Create a streaming encryption context with proper error handling
///     let mut stream = Aes128GcmEncryptStream::new(&mut encrypted, &key, None)?;
///
///     // Encrypt data in chunks
///     stream.write(b"First chunk of data")?;
///     stream.write(b"Second chunk of data")?;
///
///     // Finalize the stream
///     let writer = stream.finalize()?;
///
///     // Now decrypt the data
///     let reader = Cursor::new(encrypted); // encrypted is already a Vec<u8>
///     let mut stream = Aes128GcmDecryptStream::new(reader, &key, None)?;
///
///     // Read the decrypted data
///     let mut buffer = [0u8; 1024];
///     let bytes_read = stream.read(&mut buffer)?;
///     
///     // The decrypted data is now in buffer[..bytes_read]
///     Ok(())
/// }
/// ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::error::validate;
use algorithms::block::aes::{Aes128, Aes256};
use algorithms::aead::Gcm;
use algorithms::block::BlockCipher;
use api::traits::symmetric::SymmetricCipher as CoreSymmetricCipher;
use api::traits::symmetric::{EncryptOperation, DecryptOperation};
use api::types::{SecretBytes, Ciphertext};
// Import the new Nonce type
use algorithms::types::Nonce;
use algorithms::error::Error as PrimitiveError;

use crate::aes::keys::{Aes128Key, Aes256Key};
use crate::cipher::{SymmetricCipher as OurSymmetricCipher, Aead};

pub mod types;
pub mod aes128;
pub mod aes256;

// Re-export GCM-specific types
pub use types::{GcmNonce, AesCiphertextPackage};

/// AES-128-GCM implementation
pub struct Aes128Gcm {
    pub(crate) key: Aes128Key,
}

/// AES-256-GCM implementation
pub struct Aes256Gcm {
    pub(crate) key: Aes256Key,
}

// Bring in the per-key helper functions
pub use aes128::{
    aes128_encrypt, 
    aes128_decrypt,
    aes128_encrypt_package, 
    aes128_decrypt_package
};
pub use aes256::{
    aes256_encrypt, 
    aes256_decrypt,
    aes256_encrypt_package, 
    aes256_decrypt_package
};

impl OurSymmetricCipher for Aes128Gcm {
    type Key = Aes128Key;
    
    fn new(key: &Self::Key) -> Result<Self> {
        Ok(Self { 
            key: key.clone(),
        })
    }
    
    fn name() -> &'static str {
        "AES-128-GCM"
    }
}

impl Aead for Aes128Gcm {
    type Nonce = GcmNonce;
    
    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate nonce length
        validate::length("GCM nonce", nonce.as_bytes().len(), 12)?;
        
        // Convert key bytes to SecretBytes<16>
        let key_bytes = SecretBytes::<16>::from_slice(self.key.as_bytes())?;
        
        let aes = Aes128::new(&key_bytes);
        
        // Convert the GcmNonce to a Nonce<12>
        let primitives_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        
        // Create Gcm instance with proper error handling
        let gcm = Gcm::new(aes, &primitives_nonce)?;
        
        // Use internal_encrypt method directly
        gcm.internal_encrypt(plaintext, aad)
            .map_err(|e| Error::from(e))
    }
    
    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate nonce length
        validate::length("GCM nonce", nonce.as_bytes().len(), 12)?;
        
        // Convert key bytes to SecretBytes<16>
        let key_bytes = SecretBytes::<16>::from_slice(self.key.as_bytes())?;
        
        let aes = Aes128::new(&key_bytes);
        
        // Convert the GcmNonce to a Nonce<12>
        let primitives_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        
        // Create Gcm instance with proper error handling
        let gcm = Gcm::new(aes, &primitives_nonce)?;
        
        // Use internal_decrypt method directly with better error context
        gcm.internal_decrypt(ciphertext, aad)
            .map_err(|e| match e {
                PrimitiveError::Authentication { .. } => 
                    Error::Primitive(PrimitiveError::Authentication { 
                        algorithm: "AES-128-GCM" 
                    }),
                _ => Error::from(e),
            })
    }
    
    fn generate_nonce() -> Self::Nonce {
        GcmNonce::generate()
    }
}

impl OurSymmetricCipher for Aes256Gcm {
    type Key = Aes256Key;
    
    fn new(key: &Self::Key) -> Result<Self> {
        Ok(Self { 
            key: key.clone(),
        })
    }
    
    fn name() -> &'static str {
        "AES-256-GCM"
    }
}

impl Aead for Aes256Gcm {
    type Nonce = GcmNonce;
    
    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate nonce length
        validate::length("GCM nonce", nonce.as_bytes().len(), 12)?;
        
        // Convert key bytes to SecretBytes<32>
        let key_bytes = SecretBytes::<32>::from_slice(self.key.as_bytes())?;
        
        let aes = Aes256::new(&key_bytes);
        
        // Convert the GcmNonce to a Nonce<12>
        let primitives_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        
        // Create Gcm instance with proper error handling
        let gcm = Gcm::new(aes, &primitives_nonce)?;
        
        // Use internal_encrypt method directly
        gcm.internal_encrypt(plaintext, aad)
            .map_err(|e| Error::from(e))
    }
    
    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate nonce length
        validate::length("GCM nonce", nonce.as_bytes().len(), 12)?;
        
        // Convert key bytes to SecretBytes<32>
        let key_bytes = SecretBytes::<32>::from_slice(self.key.as_bytes())?;
        
        let aes = Aes256::new(&key_bytes);
        
        // Convert the GcmNonce to a Nonce<12>
        let primitives_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        
        // Create Gcm instance with proper error handling
        let gcm = Gcm::new(aes, &primitives_nonce)?;
        
        // Use internal_decrypt method directly with better error context
        gcm.internal_decrypt(ciphertext, aad)
            .map_err(|e| match e {
                PrimitiveError::Authentication { .. } => 
                    Error::Primitive(PrimitiveError::Authentication { 
                        algorithm: "AES-256-GCM" 
                    }),
                _ => Error::from(e),
            })
    }
    
    fn generate_nonce() -> Self::Nonce {
        GcmNonce::generate()
    }
}