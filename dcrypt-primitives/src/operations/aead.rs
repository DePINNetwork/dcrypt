//! Operations for Authenticated Encryption with Associated Data (AEAD) operations
//!
//! This module provides operation implementations for AEAD encryption and decryption
//! operations with proper parameter validation and fluent APIs.

use crate::error::{Error, Result};
use crate::operations::{Operation, WithAssociatedData, WithNonce, WithData};
use std::marker::PhantomData;

/// Common trait for AEAD operations
pub trait AeadOperation {
    /// Key type
    type Key: AsRef<[u8]>;
    
    /// Nonce type
    type Nonce: AsRef<[u8]>;
    
    /// Tag size in bytes
    const TAG_SIZE: usize;
    
    /// Algorithm name
    fn algorithm_name() -> &'static str;
}

/// Operation for AEAD encryption operations
pub struct AeadEncryptOperation<'a, T: AeadOperation> {
    /// Reference to the key
    key: &'a T::Key,
    
    /// Optional nonce
    nonce: Option<&'a T::Nonce>,
    
    /// Optional associated data
    aad: Option<&'a [u8]>,
    
    /// Optional plaintext data
    plaintext: Option<&'a [u8]>,
    
    /// Phantom data for type parameter
    _phantom: PhantomData<T>,
}

impl<'a, T: AeadOperation> AeadEncryptOperation<'a, T> {
    /// Create a new AEAD encryption builder
    pub fn new(key: &'a T::Key) -> Self {
        Self {
            key,
            nonce: None,
            aad: None,
            plaintext: None,
            _phantom: PhantomData,
        }
    }
    
    /// Encrypt the configured plaintext
    ///
    /// This method consumes the builder and produces a ciphertext with
    /// the authentication tag appended.
    pub fn encrypt(self) -> Result<Vec<u8>> {
        // Validate that all required parameters are set
        let nonce = self.nonce.ok_or_else(|| 
            Error::InvalidParameter("Nonce is required for AEAD encryption")
        )?;
        
        let plaintext = self.plaintext.ok_or_else(|| 
            Error::InvalidParameter("Plaintext is required for AEAD encryption")
        )?;
        
        // This is a placeholder - in an actual implementation,
        // this would call the algorithm-specific encryption method
        Err(Error::NotImplemented("AEAD encryption implementation"))
    }
}

impl<'a, T: AeadOperation> Operation<Vec<u8>> for AeadEncryptOperation<'a, T> {
    fn execute(self) -> Result<Vec<u8>> {
        self.encrypt()
    }
    
    fn reset(&mut self) {
        self.nonce = None;
        self.aad = None;
        self.plaintext = None;
    }
}

impl<'a, T: AeadOperation> WithNonce<'a, T::Nonce, Self> for AeadEncryptOperation<'a, T> {
    fn with_nonce(mut self, nonce: &'a T::Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

impl<'a, T: AeadOperation> WithAssociatedData<'a, Self> for AeadEncryptOperation<'a, T> {
    fn with_associated_data(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }
}

impl<'a, T: AeadOperation> WithData<'a, Self> for AeadEncryptOperation<'a, T> {
    fn with_data(mut self, data: &'a [u8]) -> Self {
        self.plaintext = Some(data);
        self
    }
}

/// Operation for AEAD decryption operations
pub struct AeadDecryptOperation<'a, T: AeadOperation> {
    /// Reference to the key
    key: &'a T::Key,
    
    /// Optional nonce
    nonce: Option<&'a T::Nonce>,
    
    /// Optional associated data
    aad: Option<&'a [u8]>,
    
    /// Optional ciphertext data
    ciphertext: Option<&'a [u8]>,
    
    /// Phantom data for type parameter
    _phantom: PhantomData<T>,
}

impl<'a, T: AeadOperation> AeadDecryptOperation<'a, T> {
    /// Create a new AEAD decryption builder
    pub fn new(key: &'a T::Key) -> Self {
        Self {
            key,
            nonce: None,
            aad: None,
            ciphertext: None,
            _phantom: PhantomData,
        }
    }
    
    /// Decrypt the configured ciphertext
    ///
    /// This method consumes the builder and produces a plaintext if
    /// authentication succeeds. If authentication fails, an error is returned.
    pub fn decrypt(self) -> Result<Vec<u8>> {
        // Validate that all required parameters are set
        let nonce = self.nonce.ok_or_else(|| 
            Error::InvalidParameter("Nonce is required for AEAD decryption")
        )?;
        
        let ciphertext = self.ciphertext.ok_or_else(|| 
            Error::InvalidParameter("Ciphertext is required for AEAD decryption")
        )?;
        
        // Ensure ciphertext is long enough to contain the authentication tag
        if ciphertext.len() < T::TAG_SIZE {
            return Err(Error::InvalidLength {
                context: "AEAD ciphertext",
                needed: T::TAG_SIZE,
                got: ciphertext.len(),
            });
        }
        
        // This is a placeholder - in an actual implementation,
        // this would call the algorithm-specific decryption method
        Err(Error::NotImplemented("AEAD decryption implementation"))
    }
}

impl<'a, T: AeadOperation> Operation<Vec<u8>> for AeadDecryptOperation<'a, T> {
    fn execute(self) -> Result<Vec<u8>> {
        self.decrypt()
    }
    
    fn reset(&mut self) {
        self.nonce = None;
        self.aad = None;
        self.ciphertext = None;
    }
}

impl<'a, T: AeadOperation> WithNonce<'a, T::Nonce, Self> for AeadDecryptOperation<'a, T> {
    fn with_nonce(mut self, nonce: &'a T::Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

impl<'a, T: AeadOperation> WithAssociatedData<'a, Self> for AeadDecryptOperation<'a, T> {
    fn with_associated_data(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }
}

impl<'a, T: AeadOperation> WithData<'a, Self> for AeadDecryptOperation<'a, T> {
    fn with_data(mut self, data: &'a [u8]) -> Self {
        self.ciphertext = Some(data);
        self
    }
}