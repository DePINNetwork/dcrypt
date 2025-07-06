//! Streaming ChaCha20Poly1305 implementations

use crate::error::{Result, validate_stream_state, SymmetricResultExt};
use crate::streaming::{StreamingEncrypt, StreamingDecrypt};
use crate::aead::chacha20poly1305::{
    ChaCha20Poly1305Key, 
    ChaCha20Poly1305Nonce, 
    ChaCha20Poly1305Cipher
};
use crate::cipher::{SymmetricCipher, Aead};
use std::io::{Read, Write};

/// Streaming encryption API for ChaCha20Poly1305 with secure nonce management
pub struct ChaCha20Poly1305EncryptStream<W: Write> {
    writer: W,
    cipher: ChaCha20Poly1305Cipher,
    buffer: Vec<u8>,
    finalized: bool,
    aad: Option<Vec<u8>>,
    // Counter for deriving unique nonces
    counter: u32,
    // Base nonce - used to derive per-chunk nonces
    base_nonce: ChaCha20Poly1305Nonce,
}

impl<W: Write> ChaCha20Poly1305EncryptStream<W> {
    /// Creates a new encryption stream
    pub fn new(writer: W, key: &ChaCha20Poly1305Key, aad: Option<&[u8]>) -> Result<Self> {
        // Create cipher with proper error handling
        let cipher = ChaCha20Poly1305Cipher::new(key)?;
        let base_nonce = ChaCha20Poly1305Cipher::generate_nonce();
        
        // Write base nonce to the beginning of the stream
        let mut w = writer;
        // Use the new error conversion trait
        w.write_all(base_nonce.as_bytes()).map_io_err()?;
        
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
    fn derive_chunk_nonce(&self) -> ChaCha20Poly1305Nonce {
        // Create a derived nonce by XORing the counter with the base nonce
        let mut nonce_bytes = *self.base_nonce.as_bytes();
        let counter_bytes = self.counter.to_be_bytes();
        
        // XOR the last 4 bytes with the counter
        for i in 0..4 {
            nonce_bytes[8 + i] ^= counter_bytes[i];
        }
        
        ChaCha20Poly1305Nonce::new(nonce_bytes)
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
        self.writer.write_all(&[1]).map_io_err()?; // 1 = has chunk nonce
        
        // Write the chunk counter (used to derive the nonce)
        let counter_bytes = self.counter.to_be_bytes();
        self.writer.write_all(&counter_bytes).map_io_err()?;
        
        // Write the length of the ciphertext followed by the ciphertext itself
        let len = (ciphertext.len() as u32).to_be_bytes();
        self.writer.write_all(&len).map_io_err()?;
        self.writer.write_all(&ciphertext).map_io_err()?;
        
        // Increment counter for next chunk
        self.counter += 1;
        
        // Clear the buffer
        self.buffer.clear();
        
        Ok(())
    }
}

impl<W: Write> StreamingEncrypt<W> for ChaCha20Poly1305EncryptStream<W> {
    /// Writes plaintext data to the stream
    fn write(&mut self, data: &[u8]) -> Result<()> {
        validate_stream_state(
            !self.finalized,
            "stream write",
            "stream already finalized"
        )?;
        
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
        validate_stream_state(
            !self.finalized,
            "stream finalize",
            "stream already finalized"
        )?;
        
        // Flush any remaining data
        self.flush_buffer()?;
        
        // Write a zero marker to indicate end of data
        self.writer.write_all(&[0]).map_io_err()?;
        
        self.finalized = true;
        Ok(self.writer)
    }
}

/// Streaming decryption API for ChaCha20Poly1305 with secure nonce handling
pub struct ChaCha20Poly1305DecryptStream<R: Read> {
    reader: R,
    cipher: ChaCha20Poly1305Cipher,
    base_nonce: ChaCha20Poly1305Nonce,
    finished: bool,
    aad: Option<Vec<u8>>,
}

impl<R: Read> ChaCha20Poly1305DecryptStream<R> {
    /// Creates a new decryption stream
    pub fn new(mut reader: R, key: &ChaCha20Poly1305Key, aad: Option<&[u8]>) -> Result<Self> {
        // Read the base nonce from the beginning of the stream
        let mut nonce_bytes = [0u8; 12];
        reader.read_exact(&mut nonce_bytes).map_io_err()?;
        
        let base_nonce = ChaCha20Poly1305Nonce::new(nonce_bytes);
        // Create cipher with proper error handling
        let cipher = ChaCha20Poly1305Cipher::new(key)?;
        
        Ok(Self {
            reader,
            cipher,
            base_nonce,
            finished: false,
            aad: aad.map(|a| a.to_vec()),
        })
    }
    
    /// Derives a chunk nonce from the base nonce and counter
    fn derive_chunk_nonce(&self, counter: u32) -> ChaCha20Poly1305Nonce {
        let mut nonce_bytes = *self.base_nonce.as_bytes();
        let counter_bytes = counter.to_be_bytes();
        
        // XOR the last 4 bytes with the counter
        for i in 0..4 {
            nonce_bytes[8 + i] ^= counter_bytes[i];
        }
        
        ChaCha20Poly1305Nonce::new(nonce_bytes)
    }
}

impl<R: Read> StreamingDecrypt<R> for ChaCha20Poly1305DecryptStream<R> {
    /// Reads and decrypts data from the stream
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.finished {
            return Ok(0);
        }
        
        // Read the chunk marker
        let mut marker = [0u8; 1];
        self.reader.read_exact(&mut marker).map_io_err()?;
        
        // Check if we've reached the end of the stream
        if marker[0] == 0 {
            self.finished = true;
            return Ok(0);
        }
        
        // Read the chunk counter
        let mut counter_bytes = [0u8; 4];
        self.reader.read_exact(&mut counter_bytes).map_io_err()?;
        let counter = u32::from_be_bytes(counter_bytes);
        
        // Derive the nonce for this chunk
        let chunk_nonce = self.derive_chunk_nonce(counter);
        
        // Read the length of the ciphertext
        let mut len_bytes = [0u8; 4];
        self.reader.read_exact(&mut len_bytes).map_io_err()?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        // Read the ciphertext
        let mut ciphertext = vec![0u8; len];
        self.reader.read_exact(&mut ciphertext).map_io_err()?;
        
        // Decrypt the chunk using the derived nonce
        let plaintext = self.cipher.decrypt(&chunk_nonce, &ciphertext, self.aad.as_deref())?;
        
        // Copy to output buffer
        let to_copy = plaintext.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&plaintext[..to_copy]);
        
        Ok(to_copy)
    }
}

/// Encrypts a file using ChaCha20Poly1305
pub fn encrypt_file<R: Read, W: Write>(
    mut reader: R, 
    writer: W, 
    key: &ChaCha20Poly1305Key, 
    aad: Option<&[u8]>
) -> Result<()> {
    // Create stream with proper error handling
    let mut stream = ChaCha20Poly1305EncryptStream::new(writer, key, aad)?;
    
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = reader.read(&mut buffer).map_io_err()?;
        if bytes_read == 0 {
            break;
        }
        
        stream.write(&buffer[..bytes_read])?;
    }
    
    stream.finalize()?;
    Ok(())
}

/// Decrypts a file using ChaCha20Poly1305
pub fn decrypt_file<R: Read, W: Write>(
    reader: R, 
    mut writer: W, 
    key: &ChaCha20Poly1305Key, 
    aad: Option<&[u8]>
) -> Result<()> {
    let mut stream = ChaCha20Poly1305DecryptStream::new(reader, key, aad)?;
    
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        writer.write_all(&buffer[..bytes_read]).map_io_err()?;
    }
    
    Ok(())
}