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

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use zeroize::Zeroize;
use subtle::ConstantTimeEq;

use crate::block::BlockCipher;
use super::super::AuthenticatedCipher;
use crate::error::{Error, Result};

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
    nonce: Vec<u8>,
    tag_len: usize,           // desired tag length in bytes
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
        assert_eq!(
            B::BLOCK_SIZE,
            GCM_BLOCK_SIZE,
            "GCM only works with 128-bit block ciphers"
        );

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
        cipher.encrypt_block(&mut h);

        Ok(Self {
            cipher,
            h,
            nonce: nonce.to_vec(),
            tag_len,
        })
    }

    /// Generate initial counter value J0
    fn generate_j0(&self) -> [u8; GCM_BLOCK_SIZE] {
        let mut j0 = [0u8; GCM_BLOCK_SIZE];
        if self.nonce.len() == 12 {
            j0[..12].copy_from_slice(&self.nonce);
            j0[15] = 1;
        } else {
            let mut g = GHash::new(&self.h);
            // Process nonce
            g.update(&self.nonce);
            // Pad to 16-byte boundary if needed
            let rem = self.nonce.len() % GCM_BLOCK_SIZE;
            if rem != 0 {
                g.update(&vec![0u8; GCM_BLOCK_SIZE - rem]);
            }
            // Append length block: (AAD_len = 0, IV_len_bits)
            g.update_lengths(0, self.nonce.len() as u64);
            j0 = g.finalize();
        }
        j0
    }

    /// Generate encryption keystream for CTR mode
    fn generate_keystream(&self, j0: &[u8; GCM_BLOCK_SIZE], data_len: usize) -> Vec<u8> {
        let num_blocks = (data_len + GCM_BLOCK_SIZE - 1) / GCM_BLOCK_SIZE;
        let mut keystream = Vec::with_capacity(num_blocks * GCM_BLOCK_SIZE);

        // Start with counter = J0 + 1
        let mut counter = *j0;
        let mut ctr_val = BigEndian::read_u32(&counter[12..16]).wrapping_add(1);
        BigEndian::write_u32(&mut counter[12..16], ctr_val);

        for _ in 0..num_blocks {
            let mut block = counter;
            self.cipher.encrypt_block(&mut block);
            keystream.extend_from_slice(&block);
            ctr_val = ctr_val.wrapping_add(1);
            BigEndian::write_u32(&mut counter[12..16], ctr_val);
        }

        keystream
    }

    /// Generate authentication tag (full 16 bytes)
    fn generate_tag(
        &self,
        j0: &[u8; GCM_BLOCK_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> [u8; GCM_TAG_SIZE] {
        let ghash_result = process_ghash(&self.h, aad, ciphertext);
        let mut tag = ghash_result;
        let mut j0_copy = *j0;
        self.cipher.encrypt_block(&mut j0_copy);
        for i in 0..GCM_TAG_SIZE {
            tag[i] ^= j0_copy[i];
        }
        tag
    }

    // Internal encrypt method with Result return type
    fn internal_encrypt(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let aad = associated_data.unwrap_or(&[]);
        let j0 = self.generate_j0();

        let mut ciphertext = Vec::with_capacity(plaintext.len() + self.tag_len);
        if !plaintext.is_empty() {
            let keystream = self.generate_keystream(&j0, plaintext.len());
            for i in 0..plaintext.len() {
                ciphertext.push(plaintext[i] ^ keystream[i]);
            }
        }

        // Append truncated tag
        let full_tag = self.generate_tag(&j0, aad, &ciphertext);
        ciphertext.extend_from_slice(&full_tag[..self.tag_len]);
        Ok(ciphertext)
    }

    // Internal decrypt method with Result return type
    fn internal_decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
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

        let j0 = self.generate_j0();
        let full_expected = self.generate_tag(&j0, aad, ciphertext_data);
        let expected_tag = &full_expected[..self.tag_len];
        if !bool::from(expected_tag.ct_eq(received_tag)) {
            return Err(Error::AuthenticationFailed);
        }

        let keystream = self.generate_keystream(&j0, ciphertext_len);
        let mut plaintext = Vec::with_capacity(ciphertext_len);
        for i in 0..ciphertext_len {
            plaintext.push(ciphertext_data[i] ^ keystream[i]);
        }
        Ok(plaintext)
    }
}

impl<B: BlockCipher> AuthenticatedCipher for Gcm<B> {
    fn new(key: &[u8], nonce: &[u8]) -> Self {
        let cipher = B::new(key);
        Self::new_with_tag_len(cipher, nonce, GCM_TAG_SIZE)
            .unwrap_or_else(|e| panic!("Failed to create GCM: {:?}", e))
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Vec<u8> {
        self.internal_encrypt(plaintext, associated_data)
            .unwrap_or_else(|e| panic!("Encryption failed: {:?}", e))
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> std::result::Result<Vec<u8>, ()> {
        self.internal_decrypt(ciphertext, associated_data).map_err(|_| ())
    }

    fn key_size() -> usize {
        B::key_size()
    }

    fn nonce_size() -> usize {
        12 // Recommended nonce size for GCM is 12 bytes
    }

    fn tag_size() -> usize {
        GCM_TAG_SIZE
    }

    fn name() -> &'static str {
        "GCM"
    }
}

#[cfg(test)]
mod tests;
