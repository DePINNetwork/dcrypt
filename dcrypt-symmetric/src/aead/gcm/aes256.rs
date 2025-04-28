//! AES-256 cipher implementations

use crate::error::{Error, Result};
use crate::aes::keys::Aes256Key;
use super::types::{GcmNonce, AesCiphertextPackage};
use super::Aes256Gcm; // This now works because Aes256Gcm is defined in mod.rs
use crate::cipher::{SymmetricCipher, Aead};
use std::io::{Read, Write};

impl Aes256Gcm {
    /// Generates a new AES-256-GCM instance with a random key
    pub fn generate() -> (Self, Aes256Key) {
        let key = Aes256Key::generate();
        let cipher = Self::new(&key);
        (cipher, key)
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
    pub fn key(&self) -> &Aes256Key {
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

/// Streaming encryption API for AES-256-GCM with secure nonce management
pub struct Aes256GcmEncryptStream<W: Write> {
    writer: W,
    cipher: Aes256Gcm,
    buffer: Vec<u8>,
    finalized: bool,
    aad: Option<Vec<u8>>,
    // Counter for deriving unique nonces
    counter: u32,
    // Base nonce - used to derive per-chunk nonces
    base_nonce: GcmNonce,
}

impl<W: Write> Aes256GcmEncryptStream<W> {
    /// Creates a new encryption stream
    pub fn new(writer: W, key: &Aes256Key, aad: Option<&[u8]>) -> Self {
        let cipher = Aes256Gcm::new(key);
        let base_nonce = Aes256Gcm::generate_nonce();
        
        // Write base nonce to the beginning of the stream
        let mut w = writer;
        w.write_all(base_nonce.as_bytes()).expect("Failed to write nonce");
        
        Self {
            writer: w,
            cipher,
            buffer: Vec::with_capacity(16384), // 16 KB buffer
            finalized: false,
            aad: aad.map(|a| a.to_vec()),
            counter: 0,
            base_nonce,
        }
    }
    
    /// Derives a unique nonce for the current chunk
    fn derive_chunk_nonce(&self) -> GcmNonce {
        // Create a derived nonce by XORing the counter with the base nonce
        let mut nonce_bytes = *self.base_nonce.as_bytes();
        let counter_bytes = self.counter.to_be_bytes();
        
        // XOR the last 4 bytes with the counter
        for i in 0..4 {
            nonce_bytes[8 + i] ^= counter_bytes[i];
        }
        
        GcmNonce::new(nonce_bytes)
    }
    
    /// Writes plaintext data to the stream
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(Error::StreamAlreadyFinalized);
        }
        
        // Add data to internal buffer
        self.buffer.extend_from_slice(data);
        
        // If buffer exceeds 16 KB, encrypt and write a chunk
        if self.buffer.len() >= 16384 {
            self.flush_buffer()?;
        }
        
        Ok(())
    }
    
    /// Flushes the internal buffer, encrypting and writing data
    fn flush_buffer(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        
        // Generate a unique nonce for this chunk using counter
        let chunk_nonce = self.derive_chunk_nonce();
        
        // Encrypt the buffered data with the unique nonce
        let ciphertext = self.cipher.encrypt(&chunk_nonce, &self.buffer, self.aad.as_deref())?;
        
        // Write the chunk nonce indicator followed by ciphertext length and data
        self.writer.write_all(&[1]).map_err(|_| Error::IoError)?; // 1 = has chunk nonce
        
        // Write the chunk counter (used to derive the nonce)
        let counter_bytes = self.counter.to_be_bytes();
        self.writer.write_all(&counter_bytes).map_err(|_| Error::IoError)?;
        
        // Write the length of the ciphertext followed by the ciphertext itself
        let len = (ciphertext.len() as u32).to_be_bytes();
        self.writer.write_all(&len).map_err(|_| Error::IoError)?;
        self.writer.write_all(&ciphertext).map_err(|_| Error::IoError)?;
        
        // Increment counter for next chunk
        self.counter += 1;
        
        // Clear the buffer
        self.buffer.clear();
        
        Ok(())
    }
    
    /// Finalizes the stream, encrypting any remaining data
    pub fn finalize(mut self) -> Result<W> {
        if self.finalized {
            return Err(Error::StreamAlreadyFinalized);
        }
        
        // Flush any remaining data
        self.flush_buffer()?;
        
        // Write a zero marker to indicate end of data
        self.writer.write_all(&[0]).map_err(|_| Error::IoError)?;
        
        self.finalized = true;
        Ok(self.writer)
    }
}

/// Streaming decryption API for AES-256-GCM with secure nonce handling
pub struct Aes256GcmDecryptStream<R: Read> {
    reader: R,
    cipher: Aes256Gcm,
    base_nonce: GcmNonce,
    finished: bool,
    aad: Option<Vec<u8>>,
}

impl<R: Read> Aes256GcmDecryptStream<R> {
    /// Creates a new decryption stream
    pub fn new(mut reader: R, key: &Aes256Key, aad: Option<&[u8]>) -> Result<Self> {
        // Read the base nonce from the beginning of the stream
        let mut nonce_bytes = [0u8; 12];
        reader.read_exact(&mut nonce_bytes).map_err(|_| Error::IoError)?;
        
        let base_nonce = GcmNonce::new(nonce_bytes);
        let cipher = Aes256Gcm::new(key);
        
        Ok(Self {
            reader,
            cipher,
            base_nonce,
            finished: false,
            aad: aad.map(|a| a.to_vec()),
        })
    }
    
    /// Derives a chunk nonce from the base nonce and counter
    fn derive_chunk_nonce(&self, counter: u32) -> GcmNonce {
        let mut nonce_bytes = *self.base_nonce.as_bytes();
        let counter_bytes = counter.to_be_bytes();
        
        // XOR the last 4 bytes with the counter
        for i in 0..4 {
            nonce_bytes[8 + i] ^= counter_bytes[i];
        }
        
        GcmNonce::new(nonce_bytes)
    }
    
    /// Reads and decrypts data from the stream
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.finished {
            return Ok(0);
        }
        
        // Read the chunk marker
        let mut marker = [0u8; 1];
        match self.reader.read_exact(&mut marker) {
            Ok(_) => {},
            Err(_) => return Err(Error::IoError)
        }
        
        // Check if we've reached the end of the stream
        if marker[0] == 0 {
            self.finished = true;
            return Ok(0);
        }
        
        // Read the chunk counter
        let mut counter_bytes = [0u8; 4];
        self.reader.read_exact(&mut counter_bytes).map_err(|_| Error::IoError)?;
        let counter = u32::from_be_bytes(counter_bytes);
        
        // Derive the nonce for this chunk
        let chunk_nonce = self.derive_chunk_nonce(counter);
        
        // Read the length of the ciphertext
        let mut len_bytes = [0u8; 4];
        self.reader.read_exact(&mut len_bytes).map_err(|_| Error::IoError)?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        // Read the ciphertext
        let mut ciphertext = vec![0u8; len];
        self.reader.read_exact(&mut ciphertext).map_err(|_| Error::IoError)?;
        
        // Decrypt the chunk using the derived nonce
        let plaintext = self.cipher.decrypt(&chunk_nonce, &ciphertext, self.aad.as_deref())?;
        
        // Copy to output buffer
        let to_copy = plaintext.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&plaintext[..to_copy]);
        
        Ok(to_copy)
    }
}

// Additional standalone functions

/// Creates a new AES-256-GCM instance with a random key and encrypts data
pub fn aes256_encrypt(plaintext: &[u8], aad: Option<&[u8]>) 
    -> Result<(Vec<u8>, Aes256Key, GcmNonce)> 
{
    let key = Aes256Key::generate();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce();
    
    let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;
    
    Ok((ciphertext, key, nonce))
}

/// Decrypts data using AES-256-GCM
pub fn aes256_decrypt(ciphertext: &[u8], key: &Aes256Key, nonce: &GcmNonce, aad: Option<&[u8]>) 
    -> Result<Vec<u8>> 
{
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, ciphertext, aad)
}

/// Encrypts data and returns a complete package with everything needed for decryption
pub fn aes256_encrypt_package(plaintext: &[u8], aad: Option<&[u8]>) 
    -> Result<(AesCiphertextPackage, Aes256Key)> 
{
    let key = Aes256Key::generate();
    let cipher = Aes256Gcm::new(&key);
    let package = cipher.encrypt_to_package(plaintext, aad)?;
    
    Ok((package, key))
}

/// Decrypts a package using the provided key
pub fn aes256_decrypt_package(package: &AesCiphertextPackage, key: &Aes256Key, aad: Option<&[u8]>) 
    -> Result<Vec<u8>> 
{
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt_package(package, aad)
}

/// Encrypts a file using AES-256-GCM
pub fn encrypt_file<R: Read, W: Write>(
    mut reader: R, 
    writer: W, 
    key: &Aes256Key, 
    aad: Option<&[u8]>
) -> Result<()> {
    let mut stream = Aes256GcmEncryptStream::new(writer, key, aad);
    
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = reader.read(&mut buffer).map_err(|_| Error::IoError)?;
        if bytes_read == 0 {
            break;
        }
        
        stream.write(&buffer[..bytes_read])?;
    }
    
    stream.finalize()?;
    Ok(())
}

/// Decrypts a file using AES-256-GCM
pub fn decrypt_file<R: Read, W: Write>(
    reader: R, 
    mut writer: W, 
    key: &Aes256Key, 
    aad: Option<&[u8]>
) -> Result<()> {
    let mut stream = Aes256GcmDecryptStream::new(reader, key, aad)?;
    
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        writer.write_all(&buffer[..bytes_read]).map_err(|_| Error::IoError)?;
    }
    
    Ok(())
}