//! ChaCha20-Poly1305 authenticated encryption
//!
//! This module implements the ChaCha20-Poly1305 AEAD algorithm as specified in
//! RFC 8439.
//!
//! ## Constant-Time Guarantees
//!
//! * No variable-length early-returns after authentication is checked.  
//! * Heap allocations and frees are balanced in both success and failure paths.
//! * Authentication is decided with a branch-free constant-time mask; the same
//!   byte-wise loop executes whatever the tag's validity.

use crate::error::{Error, Result};
use crate::stream::chacha::chacha20::{ChaCha20, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE};
use crate::mac::poly1305::{Poly1305, POLY1305_KEY_SIZE, POLY1305_TAG_SIZE};
use crate::types::SecretBytes;
use crate::types::Nonce; // Changed: Import generic Nonce type
use crate::types::Tag; // Added: Import generic Tag type
use crate::types::nonce::ChaCha20Compatible; // Added: Import the compatibility trait
use dcrypt_core::types::Ciphertext;
use dcrypt_core::traits::{AuthenticatedCipher, SymmetricCipher};
use dcrypt_core::traits::symmetric::{Operation, EncryptOperation, DecryptOperation};
use dcrypt_core::error::DcryptError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Size constants
pub const CHACHA20POLY1305_KEY_SIZE: usize = CHACHA20_KEY_SIZE;
pub const CHACHA20POLY1305_NONCE_SIZE: usize = CHACHA20_NONCE_SIZE;
pub const CHACHA20POLY1305_TAG_SIZE: usize = POLY1305_TAG_SIZE;

/// ChaCha20-Poly1305 AEAD
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ChaCha20Poly1305 {
    key: [u8; CHACHA20POLY1305_KEY_SIZE],
}

/// Operation for ChaCha20Poly1305 encryption operations
pub struct ChaCha20Poly1305EncryptOperation<'a> {
    cipher: &'a ChaCha20Poly1305,
    nonce: Option<&'a Nonce<CHACHA20POLY1305_NONCE_SIZE>>, // Changed from Nonce12 to Nonce<CHACHA20POLY1305_NONCE_SIZE>
    aad: Option<&'a [u8]>,
}

/// Operation for ChaCha20Poly1305 decryption operations
pub struct ChaCha20Poly1305DecryptOperation<'a> {
    cipher: &'a ChaCha20Poly1305,
    nonce: Option<&'a Nonce<CHACHA20POLY1305_NONCE_SIZE>>, // Changed from Nonce12 to Nonce<CHACHA20POLY1305_NONCE_SIZE>
    aad: Option<&'a [u8]>,
}

impl ChaCha20Poly1305 {
    /// Create a new instance from a 256-bit key.
    pub fn new(key: &[u8; CHACHA20POLY1305_KEY_SIZE]) -> Self {
        let mut cipher_key = [0u8; CHACHA20POLY1305_KEY_SIZE];
        cipher_key.copy_from_slice(key);
        Self { key: cipher_key }
    }

    /// Derive the one-time Poly1305 key (RFC 8439 §2.8).
    fn poly1305_key(&self, nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE]) -> [u8; POLY1305_KEY_SIZE] {
        // Create a Nonce object from the raw nonce bytes
        let nonce_obj = Nonce::<CHACHA20_NONCE_SIZE>::from_slice(nonce)
            .expect("Valid nonce"); // This should never fail in internal code
            
        let mut chacha = ChaCha20::new(&self.key, &nonce_obj);
        let mut poly_key = [0u8; POLY1305_KEY_SIZE];
        chacha.keystream(&mut poly_key);
        poly_key
    }

    /* --------------------------------------------------------------------- */
    /*                               ENCRYPT                                 */
    /* --------------------------------------------------------------------- */

    pub fn encrypt_with_nonce(
        &self,
        nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let poly_key = self.poly1305_key(nonce);

        // ciphertext || tag
        let mut ct_buf = Vec::with_capacity(plaintext.len() + POLY1305_TAG_SIZE);

        // --- encryption ----------------------------------------------------
        ct_buf.extend_from_slice(plaintext);
        
        // Create a Nonce object from the raw nonce bytes for ChaCha20
        let nonce_obj = Nonce::<CHACHA20_NONCE_SIZE>::from_slice(nonce)
            .map_err(|_| Error::InvalidParameter("Failed to create nonce"))?;
        
        ChaCha20::with_counter(&self.key, &nonce_obj, 1).encrypt(&mut ct_buf);

        // --- tag -----------------------------------------------------------
        let tag = self.calculate_tag_ct(&poly_key, aad, &ct_buf)?;
        ct_buf.extend_from_slice(tag.as_ref());
        Ok(ct_buf)
    }

    /* --------------------------------------------------------------------- */
    /*                               DECRYPT                                 */
    /* --------------------------------------------------------------------- */

    pub fn decrypt_with_nonce(
        &self,
        nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < POLY1305_TAG_SIZE {
            return Err(Error::InvalidLength {
                context: "ChaCha20Poly1305 ciphertext",
                needed: POLY1305_TAG_SIZE,
                got: ciphertext.len(),
            });
        }
        
        let ct_len = ciphertext.len() - POLY1305_TAG_SIZE;
        let (encrypted, tag) = ciphertext.split_at(ct_len);

        // -------- one-time key & expected tag ------------------------------
        let poly_key = self.poly1305_key(nonce);
        let expected = self.calculate_tag_ct(&poly_key, aad, encrypted)?;
        let tag_ok = expected.as_ref().ct_eq(tag);               // subtle::Choice

        // -------- decrypt ---------------------------------------------------
        let mut m = Vec::with_capacity(encrypted.len());
        m.extend_from_slice(encrypted);
        
        // Create a Nonce object from the raw nonce bytes for ChaCha20
        let nonce_obj = Nonce::<CHACHA20_NONCE_SIZE>::from_slice(nonce)
            .map_err(|_| Error::InvalidParameter("Failed to create nonce"))?;
        
        ChaCha20::with_counter(&self.key, &nonce_obj, 1).decrypt(&mut m);

        // -------- constant-time post-processing ----------------------------
        // mask = 0xFF when tag_ok == 1, else 0x00
        let mask = 0u8.wrapping_sub(tag_ok.unwrap_u8());
        
        // Apply mask to all bytes
        for byte in &mut m {
            *byte &= mask;
        }
        
        // Create a burn buffer on success path to match the deallocation in failure path
        // This ensures both paths perform identical memory operations
        let mut burn = m.clone();
        for b in &mut burn { *b = 0; }  // wipe
        drop(burn);

        if bool::from(tag_ok) {
            Ok(m)  // m lives on success
        } else {
            Err(Error::AuthenticationFailed)  // drops m on failure
        }
    }

    /* --------------------------------------------------------------------- */
    /*                               TAG CT                                  */
    /* --------------------------------------------------------------------- */

    /// RFC 8439 §2.8: constant-time Poly1305 tag computation.
    fn calculate_tag_ct(
        &self,
        poly_key: &[u8; POLY1305_KEY_SIZE],
        aad: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Tag<POLY1305_TAG_SIZE>> {
        let mut poly = Poly1305::new(poly_key);
        let aad_slice = aad.unwrap_or(&[]);

        const ZERO16: [u8; 16] = [0u8; 16];

        // AAD
        poly.update(aad_slice)?;
        poly.update(&ZERO16[..(16 - aad_slice.len() % 16) % 16])?;

        // ciphertext
        poly.update(ciphertext)?;
        poly.update(&ZERO16[..(16 - ciphertext.len() % 16) % 16])?;

        // length block
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(aad_slice.len() as u64).to_le_bytes());
        len_block[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        poly.update(&len_block)?;

        // Get the finalized tag - it's already a Tag<16> so return directly
        let tag = poly.finalize();
        Ok(tag)
    }
    
    /// Encrypt data
    pub fn encrypt<const N: usize>(
        &self,
        nonce: &Nonce<N>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> 
    where 
        Nonce<N>: ChaCha20Compatible
    {
        let mut nonce_array = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        nonce_array.copy_from_slice(nonce.as_ref());
        self.encrypt_with_nonce(&nonce_array, plaintext, aad)
    }
    
    /// Decrypt data
    pub fn decrypt<const N: usize>(
        &self,
        nonce: &Nonce<N>,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> 
    where 
        Nonce<N>: ChaCha20Compatible
    {
        let mut nonce_array = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        nonce_array.copy_from_slice(nonce.as_ref());
        self.decrypt_with_nonce(&nonce_array, ciphertext, aad)
    }
}

// Implement the marker trait AuthenticatedCipher
impl AuthenticatedCipher for ChaCha20Poly1305 {
    const TAG_SIZE: usize = POLY1305_TAG_SIZE;
    const ALGORITHM_ID: &'static str = "ChaCha20Poly1305";
}

// Implement SymmetricCipher trait
impl SymmetricCipher for ChaCha20Poly1305 {
    type Key = SecretBytes<CHACHA20POLY1305_KEY_SIZE>;
    type Nonce = Nonce<CHACHA20POLY1305_NONCE_SIZE>; // Changed from Nonce12 to Nonce<CHACHA20POLY1305_NONCE_SIZE>
    type Ciphertext = Ciphertext;
    type EncryptOperation<'a> = ChaCha20Poly1305EncryptOperation<'a> where Self: 'a;
    type DecryptOperation<'a> = ChaCha20Poly1305DecryptOperation<'a> where Self: 'a;
    
    fn name() -> &'static str {
        "ChaCha20Poly1305"
    }
    
    fn encrypt<'a>(&'a self) -> Self::EncryptOperation<'a> {
        ChaCha20Poly1305EncryptOperation {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }
    
    fn decrypt<'a>(&'a self) -> Self::DecryptOperation<'a> {
        ChaCha20Poly1305DecryptOperation {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }
    
    fn generate_key<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> std::result::Result<Self::Key, DcryptError> {
        let mut key_data = [0u8; CHACHA20POLY1305_KEY_SIZE];
        rng.fill_bytes(&mut key_data);
        Ok(SecretBytes::new(key_data))
    }
    
    fn generate_nonce<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> std::result::Result<Self::Nonce, DcryptError> {
        let mut nonce_data = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        rng.fill_bytes(&mut nonce_data);
        Ok(Nonce::new(nonce_data)) // Changed: Using generic Nonce constructor instead of Nonce12
    }
    
    fn derive_key_from_bytes(bytes: &[u8]) -> std::result::Result<Self::Key, DcryptError> {
        if bytes.len() < CHACHA20POLY1305_KEY_SIZE {
            return Err(DcryptError::InvalidLength {
                context: "ChaCha20Poly1305 key derivation",
                expected: CHACHA20POLY1305_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        
        let mut key_data = [0u8; CHACHA20POLY1305_KEY_SIZE];
        key_data.copy_from_slice(&bytes[..CHACHA20POLY1305_KEY_SIZE]);
        Ok(SecretBytes::new(key_data))
    }
}

// Implement Operation for ChaCha20Poly1305EncryptOperation
impl<'a> Operation<Ciphertext> for ChaCha20Poly1305EncryptOperation<'a> {
    fn execute(self) -> std::result::Result<Ciphertext, DcryptError> {
        let nonce = self.nonce.ok_or_else(|| DcryptError::InvalidParameter {
            context: "ChaCha20Poly1305 encryption",
            #[cfg(feature = "std")]
            message: "Nonce is required for ChaCha20Poly1305 encryption".to_string(),
        })?;
        
        let plaintext = b""; // Default empty plaintext
        
        let mut nonce_array = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        nonce_array.copy_from_slice(nonce.as_ref());
        
        let ciphertext = self.cipher.encrypt_with_nonce(
            &nonce_array,
            plaintext,
            self.aad,
        ).map_err(|e| DcryptError::from(e))?;
        
        Ok(Ciphertext::new(&ciphertext))
    }
}

impl<'a> EncryptOperation<'a, ChaCha20Poly1305> for ChaCha20Poly1305EncryptOperation<'a> {
    fn with_nonce(mut self, nonce: &'a <ChaCha20Poly1305 as SymmetricCipher>::Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }
    
    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }
    
    fn encrypt(self, plaintext: &'a [u8]) -> std::result::Result<Ciphertext, DcryptError> {
        let nonce = self.nonce.ok_or_else(|| DcryptError::InvalidParameter {
            context: "ChaCha20Poly1305 encryption",
            #[cfg(feature = "std")]
            message: "Nonce is required for ChaCha20Poly1305 encryption".to_string(),
        })?;
        
        let mut nonce_array = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        nonce_array.copy_from_slice(nonce.as_ref());
        
        let ciphertext = self.cipher.encrypt_with_nonce(
            &nonce_array,
            plaintext,
            self.aad,
        ).map_err(|e| DcryptError::from(e))?;
        
        Ok(Ciphertext::new(&ciphertext))
    }
}

// Implement Operation for ChaCha20Poly1305DecryptOperation
impl<'a> Operation<Vec<u8>> for ChaCha20Poly1305DecryptOperation<'a> {
    fn execute(self) -> std::result::Result<Vec<u8>, DcryptError> {
        Err(DcryptError::InvalidParameter {
            context: "ChaCha20Poly1305 decryption",
            #[cfg(feature = "std")]
            message: "Use decrypt method instead".to_string(),
        })
    }
}

impl<'a> DecryptOperation<'a, ChaCha20Poly1305> for ChaCha20Poly1305DecryptOperation<'a> {
    fn with_nonce(mut self, nonce: &'a <ChaCha20Poly1305 as SymmetricCipher>::Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }
    
    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }
    
    fn decrypt(self, ciphertext: &'a <ChaCha20Poly1305 as SymmetricCipher>::Ciphertext) -> std::result::Result<Vec<u8>, DcryptError> {
        let nonce = self.nonce.ok_or_else(|| DcryptError::InvalidParameter {
            context: "ChaCha20Poly1305 decryption",
            #[cfg(feature = "std")]
            message: "Nonce is required for ChaCha20Poly1305 decryption".to_string(),
        })?;
        
        let mut nonce_array = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        nonce_array.copy_from_slice(nonce.as_ref());
        
        self.cipher.decrypt_with_nonce(
            &nonce_array,
            ciphertext.as_ref(),
            self.aad,
        ).map_err(|e| DcryptError::from(e))
    }
}

#[cfg(test)]
mod tests;