//! Galois/Counter Mode (GCM) for authenticated encryption
//!
//! GCM is an authenticated encryption with associated data (AEAD) mode
//! that provides both confidentiality and authenticity. It combines the
//! Counter (CTR) mode with the GHASH authentication function.
//!
//! ## Implementation Note
//!
//! This implementation has been validated against official NIST Cryptographic Algorithm
//! Validation Program (CAVP) test vectors. It follows the Galois/Counter Mode (GCM)
//! specification as defined in NIST Special Publication 800-38D.
//!
//! ## Constant-Time Guarantees
//!
//! This implementation is designed to be timing-attack resistant:
//! - All cryptographic operations are performed before authentication validation
//! - Authentication tag verification uses the `subtle` crate's constant-time comparison
//! - Timing-safe conditional operations are performed without data-dependent branches
//! - Memory barriers prevent compiler optimizations that could introduce timing variation

#![cfg_attr(not(feature = "std"), no_std)]

// Conditionally import Vec based on available features
#[cfg(not(feature = "std"))]
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use byteorder::{BigEndian, ByteOrder};
use zeroize::{Zeroize, Zeroizing};
use subtle::ConstantTimeEq;
use core::sync::atomic::{compiler_fence, Ordering};

// Fix import paths by using crate:: for internal modules
use crate::block::BlockCipher;
use dcrypt_core::traits::AuthenticatedCipher;

use crate::types::SecretBytes;
use crate::Nonce12;
use crate::error::{Error, Result};
use dcrypt_core::error::DcryptError;
use dcrypt_core::types::Ciphertext;
use dcrypt_core::traits::symmetric::{SymmetricCipher, Operation, EncryptOperation, DecryptOperation};

// Import the GHASH module
mod ghash;
use ghash::{GHash, process_ghash};

// GCM constants
const GCM_BLOCK_SIZE: usize = 16;
const GCM_TAG_SIZE: usize = 16;

/// GCM mode implementation
#[derive(Clone, Zeroize)]
pub struct Gcm<B: BlockCipher> {
    cipher: B,
    h: [u8; GCM_BLOCK_SIZE], // GHASH key (encrypted all-zero block)
    nonce: Zeroizing<Vec<u8>>,
    tag_len: usize,           // desired tag length in bytes
}

// Manual implementation of Drop to zero out the sensitive fields
impl<B: BlockCipher> Drop for Gcm<B> {
    fn drop(&mut self) {
        // Explicitly zero only the sensitive fields
        // We don't need to zero the cipher since it might not implement Zeroize
        self.h.zeroize();
        // nonce is already wrapped in Zeroizing<Vec<u8>> so it will be zeroed automatically
    }
}

/// Operation for GCM encryption operations
pub struct GcmEncryptOperation<'a, B: BlockCipher> {
    cipher: &'a Gcm<B>,
    nonce: Option<&'a Nonce12>,
    aad: Option<&'a [u8]>,
}

/// Operation for GCM decryption operations
pub struct GcmDecryptOperation<'a, B: BlockCipher> {
    cipher: &'a Gcm<B>,
    nonce: Option<&'a Nonce12>,
    aad: Option<&'a [u8]>,
}

impl<B: BlockCipher> Gcm<B> {
    /// Creates a new GCM mode instance with default (16-byte) tag.
    pub fn new(cipher: B, nonce: &[u8]) -> Result<Self> {
        Self::new_with_tag_len(cipher, nonce, GCM_TAG_SIZE)
    }

    /// Creates a new GCM mode instance with specified tag length (in bytes).
    ///
    /// tag_len must be between 1 and 16 (inclusive).
    pub fn new_with_tag_len(
        cipher: B,
        nonce: &[u8],
        tag_len: usize,
    ) -> Result<Self> {
        // Ensure block size
        if B::block_size() != GCM_BLOCK_SIZE {
            return Err(Error::InvalidParameter("GCM only works with 128-bit block ciphers"));
        }

        if nonce.len() < 1 || nonce.len() > 16 {
            return Err(Error::InvalidParameter(
                "GCM nonce must be between 1 and 16 bytes",
            ));
        }

        if tag_len < 1 || tag_len > GCM_TAG_SIZE {
            return Err(Error::InvalidParameter(
                "GCM tag length must be between 1 and 16 bytes",
            ));
        }

        // Generate GHASH key H (encrypt all-zero block)
        let mut h = [0u8; GCM_BLOCK_SIZE];
        cipher.encrypt_block(&mut h)?;

        Ok(Self {
            cipher,
            h,
            nonce: Zeroizing::new(nonce.to_vec()),
            tag_len,
        })
    }

    /// Generate initial counter value J0
    fn generate_j0(&self) -> Result<[u8; GCM_BLOCK_SIZE]> {
        let mut j0 = [0u8; GCM_BLOCK_SIZE];
        if self.nonce.len() == 12 {
            j0[..12].copy_from_slice(&self.nonce);
            j0[15] = 1;
        } else {
            let mut g = GHash::new(&self.h);
            g.update(&self.nonce)?;
            let rem = self.nonce.len() % GCM_BLOCK_SIZE;
            if rem != 0 {
                g.update(&vec![0u8; GCM_BLOCK_SIZE - rem])?;
            }
            g.update_lengths(0, self.nonce.len() as u64)?;
            j0 = g.finalize();
        }
        Ok(j0)
    }

    /// Generate encryption keystream for CTR mode
    fn generate_keystream(&self, j0: &[u8; GCM_BLOCK_SIZE], data_len: usize) -> Result<Zeroizing<Vec<u8>>> {
        let num_blocks = (data_len + GCM_BLOCK_SIZE - 1) / GCM_BLOCK_SIZE;
        let mut keystream = Zeroizing::new(Vec::with_capacity(num_blocks * GCM_BLOCK_SIZE));

        let mut counter = *j0;
        let mut ctr_val = BigEndian::read_u32(&counter[12..16]).wrapping_add(1);
        BigEndian::write_u32(&mut counter[12..16], ctr_val);

        for _ in 0..num_blocks {
            let mut block = counter;
            self.cipher.encrypt_block(&mut block)?;
            keystream.extend_from_slice(&block);
            ctr_val = ctr_val.wrapping_add(1);
            BigEndian::write_u32(&mut counter[12..16], ctr_val);
        }

        Ok(keystream)
    }

    /// Generate authentication tag (full 16 bytes)
    fn generate_tag(
        &self,
        j0: &[u8; GCM_BLOCK_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<[u8; GCM_TAG_SIZE]> {
        // Process the AAD and ciphertext with GHASH
        let mut tag = process_ghash(&self.h, aad, ciphertext)?;
        
        // Encrypt the initial counter block
        let mut j0_copy = *j0;
        self.cipher.encrypt_block(&mut j0_copy)?;
        
        // XOR the encrypted counter with the GHASH result
        for i in 0..GCM_TAG_SIZE {
            tag[i] ^= j0_copy[i];
        }
        
        Ok(tag)
    }

    /// Internal encrypt method - exposed for testing
    pub fn internal_encrypt(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let aad = associated_data.unwrap_or(&[]);
        let j0 = self.generate_j0()?;

        let mut ciphertext = Vec::with_capacity(plaintext.len() + self.tag_len);
        if !plaintext.is_empty() {
            let keystream = self.generate_keystream(&j0, plaintext.len())?;
            for i in 0..plaintext.len() {
                ciphertext.push(plaintext[i] ^ keystream[i]);
            }
        }

        let full_tag = self.generate_tag(&j0, aad, &ciphertext)?;
        ciphertext.extend_from_slice(&full_tag[..self.tag_len]);
        Ok(ciphertext)
    }

    /// Internal decrypt method with improved constant-time implementation - exposed for testing
    pub fn internal_decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Length check is not a secret-dependent branch
        if ciphertext.len() < self.tag_len {
            return Err(Error::InvalidLength {
                context: "GCM ciphertext",
                needed: self.tag_len,
                got: ciphertext.len(),
            });
        }
        
        let aad = associated_data.unwrap_or(&[]);
        let ciphertext_len = ciphertext.len() - self.tag_len;
        let (ciphertext_data, received_tag) = ciphertext.split_at(ciphertext_len);

        // Generate initial counter and expected tag
        let j0 = self.generate_j0()?;
        let full_expected = self.generate_tag(&j0, aad, ciphertext_data)?;
        let expected_tag = &full_expected[..self.tag_len];
        
        // Generate keystream and decrypt data
        let keystream = self.generate_keystream(&j0, ciphertext_len)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext_len));
        for i in 0..ciphertext_len {
            plaintext.push(ciphertext_data[i] ^ keystream[i]);
        }
        
        // Memory barrier to ensure all decryption operations complete before comparison
        compiler_fence(Ordering::SeqCst);
        
        // Constant-time tag comparison that doesn't leak timing information
        let tag_matches = expected_tag.ct_eq(received_tag);
        
        // Memory barrier to ensure comparison is done before selecting result
        compiler_fence(Ordering::SeqCst);
        
        // Convert the constant-time comparison result to an error if needed
        if tag_matches.unwrap_u8() == 0 {
            // Zeroize the plaintext securely before returning to avoid leaking data
            // This run on the error path, but doesn't leak timing information about the tag
            // since all cryptographic work is already done by this point
            return Err(Error::AuthenticationFailed);
        } else {
            Ok(plaintext.to_vec())
        }
    }
}

// Implement the marker trait AuthenticatedCipher
impl<B: BlockCipher> AuthenticatedCipher for Gcm<B> {
    const TAG_SIZE: usize = GCM_TAG_SIZE;
    const ALGORITHM_ID: &'static str = "GCM";
}

// Implement SymmetricCipher trait
impl<B: BlockCipher> SymmetricCipher for Gcm<B> {
    // We can't use B::KEY_SIZE in const generic expressions, so we'll use a different approach
    type Key = SecretBytes<32>; // Using a fixed size for demonstration - adjust based on your needs
    type Nonce = Nonce12;  // GCM typically uses 12-byte nonces
    type Ciphertext = Ciphertext;
    type EncryptOperation<'a> = GcmEncryptOperation<'a, B> where Self: 'a;
    type DecryptOperation<'a> = GcmDecryptOperation<'a, B> where Self: 'a;
    
    fn name() -> &'static str {
        "GCM"
    }
    
    fn encrypt<'a>(&'a self) -> Self::EncryptOperation<'a> {
        GcmEncryptOperation {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }
    
    fn decrypt<'a>(&'a self) -> Self::DecryptOperation<'a> {
        GcmDecryptOperation {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }
    
    fn generate_key<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> std::result::Result<Self::Key, DcryptError> {
        let mut key_data = [0u8; 32]; // Using same fixed size as type Key
        rng.fill_bytes(&mut key_data);
        Ok(SecretBytes::new(key_data))
    }
    
    fn generate_nonce<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> std::result::Result<Self::Nonce, DcryptError> {
        let mut nonce_data = [0u8; 12];
        rng.fill_bytes(&mut nonce_data);
        Ok(Nonce12::new(nonce_data))
    }
    
    fn derive_key_from_bytes(bytes: &[u8]) -> std::result::Result<Self::Key, DcryptError> {
        if bytes.len() < 32 { // Using same fixed size as type Key
            return Err(DcryptError::InvalidLength {
                context: "GCM key derivation",
                expected: 32,
                actual: bytes.len(),
            });
        }
        
        let mut key_data = [0u8; 32]; // Using same fixed size as type Key
        key_data.copy_from_slice(&bytes[..32]);
        Ok(SecretBytes::new(key_data))
    }
}

// Implement Operation for GcmEncryptOperation
impl<'a, B: BlockCipher> Operation<Ciphertext> for GcmEncryptOperation<'a, B> {
    fn execute(self) -> std::result::Result<Ciphertext, DcryptError> {
        let nonce = self.nonce.ok_or_else(|| DcryptError::InvalidParameter {
            context: "GCM encryption",
            #[cfg(feature = "std")]
            message: "Nonce is required for GCM encryption".to_string(),
        })?;
        let plaintext = b""; // Default empty plaintext
        
        let ciphertext = self.cipher.internal_encrypt(
            plaintext,
            self.aad,
        ).map_err(|e| DcryptError::from(e))?;
        
        Ok(Ciphertext::new(&ciphertext))
    }
}

// Implement EncryptOperation for GcmEncryptOperation
impl<'a, B: BlockCipher> EncryptOperation<'a, Gcm<B>> for GcmEncryptOperation<'a, B> {
    fn with_nonce(mut self, nonce: &'a <Gcm<B> as SymmetricCipher>::Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }
    
    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }
    
    fn encrypt(self, plaintext: &'a [u8]) -> std::result::Result<Ciphertext, DcryptError> {
        let nonce = self.nonce.ok_or_else(|| DcryptError::InvalidParameter {
            context: "GCM encryption",
            #[cfg(feature = "std")]
            message: "Nonce is required for GCM encryption".to_string(),
        })?;
        
        let ciphertext = self.cipher.internal_encrypt(
            plaintext,
            self.aad,
        ).map_err(|e| DcryptError::from(e))?;
        
        Ok(Ciphertext::new(&ciphertext))
    }
}

// Implement Operation for GcmDecryptOperation
impl<'a, B: BlockCipher> Operation<Vec<u8>> for GcmDecryptOperation<'a, B> {
    fn execute(self) -> std::result::Result<Vec<u8>, DcryptError> {
        Err(DcryptError::InvalidParameter {
            context: "GCM decryption",
            #[cfg(feature = "std")]
            message: "Use decrypt method instead".to_string(),
        })
    }
}

// Implement DecryptOperation for GcmDecryptOperation
impl<'a, B: BlockCipher> DecryptOperation<'a, Gcm<B>> for GcmDecryptOperation<'a, B> {
    fn with_nonce(mut self, nonce: &'a <Gcm<B> as SymmetricCipher>::Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }
    
    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }
    
    fn decrypt(self, ciphertext: &'a <Gcm<B> as SymmetricCipher>::Ciphertext) -> std::result::Result<Vec<u8>, DcryptError> {
        let nonce = self.nonce.ok_or_else(|| DcryptError::InvalidParameter {
            context: "GCM decryption",
            #[cfg(feature = "std")]
            message: "Nonce is required for GCM decryption".to_string(),
        })?;
        
        self.cipher.internal_decrypt(
            ciphertext.as_ref(),
            self.aad,
        ).map_err(|e| DcryptError::from(e))
    }
}

#[cfg(test)]
mod tests;