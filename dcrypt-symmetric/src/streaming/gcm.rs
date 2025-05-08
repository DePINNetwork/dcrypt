//! Streaming AES-GCM implementations

use crate::error::{Error, Result};
use crate::aead::gcm::{
    Aes128Gcm, Aes256Gcm, GcmNonce, AesCiphertextPackage
};
use crate::aes::keys::{Aes128Key, Aes256Key};
use crate::cipher::{SymmetricCipher, Aead};
use super::{StreamingEncrypt, StreamingDecrypt};
use std::io::{Read, Write};

/// Streaming encryption API for AES-128-GCM with secure nonce management
pub struct Aes128GcmEncryptStream<W: Write> {
    writer: W,
    cipher: Aes128Gcm,
    buffer: Vec<u8>,
    finalized: bool,
    aad: Option<Vec<u8>>,
    // Counter for deriving unique nonces
    counter: u32,
    // Base nonce - used to derive per-chunk nonces
    base_nonce: GcmNonce,
}

impl<W: Write> Aes128GcmEncryptStream<W> {
    /// Creates a new encryption stream
    pub fn new(writer: W, key: &Aes128Key, aad: Option<&[u8]>) -> Result<Self> {
        // Create cipher with proper error handling
        let cipher = Aes128Gcm::new(key)?;
        let base_nonce = Aes128Gcm::generate_nonce();
        
        // Write base nonce to the beginning of the stream
        let mut w = writer;
        // Use ? for error propagation instead of expect()
        w.write_all(base_nonce.as_bytes())?;
        
        Ok(Self {
            writer: w,
            cipher,
            buffer: Vec::with_capacity(16384), // 16 KB buffer
            finalized: false,
            aad: aad.map(|a| a.to_vec()),
            counter: 0,
            base_nonce,
        })
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
    
    /// Flushes the internal buffer, encrypting and writing data
    fn flush_buffer(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        
        // Generate a unique nonce for this chunk using counter
        let chunk_nonce = self.derive_chunk_nonce();
        
        // Encrypt the buffered data with the unique nonce - use ? for error propagation
        let ciphertext = self.cipher.encrypt(&chunk_nonce, &self.buffer, self.aad.as_deref())?;
        
        // Write the chunk nonce indicator followed by ciphertext length and data
        self.writer.write_all(&[1])?; // 1 = has chunk nonce
        
        // Write the chunk counter (used to derive the nonce)
        let counter_bytes = self.counter.to_be_bytes();
        self.writer.write_all(&counter_bytes)?;
        
        // Write the length of the ciphertext followed by the ciphertext itself
        let len = (ciphertext.len() as u32).to_be_bytes();
        self.writer.write_all(&len)?;
        self.writer.write_all(&ciphertext)?;
        
        // Increment counter for next chunk
        self.counter += 1;
        
        // Clear the buffer
        self.buffer.clear();
        
        Ok(())
    }
}

impl<W: Write> StreamingEncrypt<W> for Aes128GcmEncryptStream<W> {
    /// Writes plaintext data to the stream
    fn write(&mut self, data: &[u8]) -> Result<()> {
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
    
    /// Finalizes the stream, encrypting any remaining data
    fn finalize(mut self) -> Result<W> {
        if self.finalized {
            return Err(Error::StreamAlreadyFinalized);
        }
        
        // Flush any remaining data
        self.flush_buffer()?;
        
        // Write a zero marker to indicate end of data
        self.writer.write_all(&[0])?;
        
        self.finalized = true;
        Ok(self.writer)
    }
}

/// Streaming decryption API for AES-128-GCM with secure nonce handling
pub struct Aes128GcmDecryptStream<R: Read> {
    reader: R,
    cipher: Aes128Gcm,
    base_nonce: GcmNonce,
    finished: bool,
    aad: Option<Vec<u8>>,
}

impl<R: Read> Aes128GcmDecryptStream<R> {
    /// Creates a new decryption stream
    pub fn new(mut reader: R, key: &Aes128Key, aad: Option<&[u8]>) -> Result<Self> {
        // Read the base nonce from the beginning of the stream
        let mut nonce_bytes = [0u8; 12];
        reader.read_exact(&mut nonce_bytes)?;
        
        let base_nonce = GcmNonce::new(nonce_bytes);
        // Create cipher with proper error handling
        let cipher = Aes128Gcm::new(key)?;
        
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
}

impl<R: Read> StreamingDecrypt<R> for Aes128GcmDecryptStream<R> {
    /// Reads and decrypts data from the stream
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.finished {
            return Ok(0);
        }
        
        // Read the chunk marker
        let mut marker = [0u8; 1];
        self.reader.read_exact(&mut marker)?;
        
        // Check if we've reached the end of the stream
        if marker[0] == 0 {
            self.finished = true;
            return Ok(0);
        }
        
        // Read the chunk counter
        let mut counter_bytes = [0u8; 4];
        self.reader.read_exact(&mut counter_bytes)?;
        let counter = u32::from_be_bytes(counter_bytes);
        
        // Derive the nonce for this chunk
        let chunk_nonce = self.derive_chunk_nonce(counter);
        
        // Read the length of the ciphertext
        let mut len_bytes = [0u8; 4];
        self.reader.read_exact(&mut len_bytes)?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        // Read the ciphertext
        let mut ciphertext = vec![0u8; len];
        self.reader.read_exact(&mut ciphertext)?;
        
        // Decrypt the chunk using the derived nonce
        let plaintext = self.cipher.decrypt(&chunk_nonce, &ciphertext, self.aad.as_deref())?;
        
        // Copy to output buffer
        let to_copy = plaintext.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&plaintext[..to_copy]);
        
        Ok(to_copy)
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
    pub fn new(writer: W, key: &Aes256Key, aad: Option<&[u8]>) -> Result<Self> {
        // Create cipher with proper error handling
        let cipher = Aes256Gcm::new(key)?;
        let base_nonce = Aes256Gcm::generate_nonce();
        
        // Write base nonce to the beginning of the stream
        let mut w = writer;
        // Use ? for error propagation instead of expect()
        w.write_all(base_nonce.as_bytes())?;
        
        Ok(Self {
            writer: w,
            cipher,
            buffer: Vec::with_capacity(16384), // 16 KB buffer
            finalized: false,
            aad: aad.map(|a| a.to_vec()),
            counter: 0,
            base_nonce,
        })
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
        self.writer.write_all(&[1])?; // 1 = has chunk nonce
        
        // Write the chunk counter (used to derive the nonce)
        let counter_bytes = self.counter.to_be_bytes();
        self.writer.write_all(&counter_bytes)?;
        
        // Write the length of the ciphertext followed by the ciphertext itself
        let len = (ciphertext.len() as u32).to_be_bytes();
        self.writer.write_all(&len)?;
        self.writer.write_all(&ciphertext)?;
        
        // Increment counter for next chunk
        self.counter += 1;
        
        // Clear the buffer
        self.buffer.clear();
        
        Ok(())
    }
}

impl<W: Write> StreamingEncrypt<W> for Aes256GcmEncryptStream<W> {
    /// Writes plaintext data to the stream
    fn write(&mut self, data: &[u8]) -> Result<()> {
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
    
    /// Finalizes the stream, encrypting any remaining data
    fn finalize(mut self) -> Result<W> {
        if self.finalized {
            return Err(Error::StreamAlreadyFinalized);
        }
        
        // Flush any remaining data
        self.flush_buffer()?;
        
        // Write a zero marker to indicate end of data
        self.writer.write_all(&[0])?;
        
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
        reader.read_exact(&mut nonce_bytes)?;
        
        let base_nonce = GcmNonce::new(nonce_bytes);
        // Create cipher with proper error handling
        let cipher = Aes256Gcm::new(key)?;
        
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
}

impl<R: Read> StreamingDecrypt<R> for Aes256GcmDecryptStream<R> {
    /// Reads and decrypts data from the stream
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.finished {
            return Ok(0);
        }
        
        // Read the chunk marker
        let mut marker = [0u8; 1];
        self.reader.read_exact(&mut marker)?;
        
        // Check if we've reached the end of the stream
        if marker[0] == 0 {
            self.finished = true;
            return Ok(0);
        }
        
        // Read the chunk counter
        let mut counter_bytes = [0u8; 4];
        self.reader.read_exact(&mut counter_bytes)?;
        let counter = u32::from_be_bytes(counter_bytes);
        
        // Derive the nonce for this chunk
        let chunk_nonce = self.derive_chunk_nonce(counter);
        
        // Read the length of the ciphertext
        let mut len_bytes = [0u8; 4];
        self.reader.read_exact(&mut len_bytes)?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        // Read the ciphertext
        let mut ciphertext = vec![0u8; len];
        self.reader.read_exact(&mut ciphertext)?;
        
        // Decrypt the chunk using the derived nonce
        let plaintext = self.cipher.decrypt(&chunk_nonce, &ciphertext, self.aad.as_deref())?;
        
        // Copy to output buffer
        let to_copy = plaintext.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&plaintext[..to_copy]);
        
        Ok(to_copy)
    }
}

/// Encrypts a file using AES-128-GCM
pub fn encrypt_file_aes128<R: Read, W: Write>(
    mut reader: R, 
    writer: W, 
    key: &Aes128Key, 
    aad: Option<&[u8]>
) -> Result<()> {
    // Create stream with proper error handling
    let mut stream = Aes128GcmEncryptStream::new(writer, key, aad)?;
    
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        stream.write(&buffer[..bytes_read])?;
    }
    
    stream.finalize()?;
    Ok(())
}

/// Decrypts a file using AES-128-GCM
pub fn decrypt_file_aes128<R: Read, W: Write>(
    reader: R, 
    mut writer: W, 
    key: &Aes128Key, 
    aad: Option<&[u8]>
) -> Result<()> {
    let mut stream = Aes128GcmDecryptStream::new(reader, key, aad)?;
    
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        writer.write_all(&buffer[..bytes_read])?;
    }
    
    Ok(())
}

/// Encrypts a file using AES-256-GCM
pub fn encrypt_file_aes256<R: Read, W: Write>(
    mut reader: R, 
    writer: W, 
    key: &Aes256Key, 
    aad: Option<&[u8]>
) -> Result<()> {
    // Create stream with proper error handling
    let mut stream = Aes256GcmEncryptStream::new(writer, key, aad)?;
    
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        stream.write(&buffer[..bytes_read])?;
    }
    
    stream.finalize()?;
    Ok(())
}

/// Decrypts a file using AES-256-GCM
pub fn decrypt_file_aes256<R: Read, W: Write>(
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
        
        writer.write_all(&buffer[..bytes_read])?;
    }
    
    Ok(())
}