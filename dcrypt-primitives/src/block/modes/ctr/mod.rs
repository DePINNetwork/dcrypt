//! Counter (CTR) mode of operation for block ciphers
//!
//! Counter mode turns a block cipher into a stream cipher by encrypting
//! successive values of a counter and XORing the result with the plaintext.
//!
//! This implementation follows NIST SP 800-38A recommendations for CTR mode,
//! using a flexible nonce-counter format.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use byteorder::{ByteOrder, BigEndian};
use zeroize::Zeroize;

use super::super::BlockCipher;

/// Counter position within the counter block
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CounterPosition {
    /// Counter is placed at the beginning of the block (bytes 0 to counter_size-1)
    /// This is common in some implementations, especially with 8-byte counters
    Prefix,
    
    /// Counter is placed at the end of the block (last counter_size bytes)
    /// This is the most common arrangement for AES-CTR
    Postfix,
    
    /// Counter is placed at a specific offset within the block
    /// Allows for custom layouts
    Custom(usize),
}

/// Counter mode implementation
#[derive(Clone, Zeroize)]
pub struct Ctr<B: BlockCipher> {
    cipher: B,
    counter_block: Vec<u8>,
    counter_position: usize,
    counter_size: usize,
    keystream: Vec<u8>,
    keystream_pos: usize,
}

impl<B: BlockCipher> Ctr<B> {
    /// Creates a new CTR mode instance with the default configuration
    /// 
    /// * `cipher` - The block cipher to use
    /// * `nonce` - The nonce (must be at most block_size - 4 bytes)
    ///
    /// This creates a standard CTR mode with the counter in the last 4 bytes
    /// and the nonce filling the beginning of the counter block.
    pub fn new(cipher: B, nonce: &[u8]) -> Self {
        // Standard CTR mode with 4-byte counter at the end
        Self::with_counter_params(cipher, nonce, CounterPosition::Postfix, 4)
    }
    
    /// Creates a new CTR mode instance with custom counter parameters
    ///
    /// * `cipher` - The block cipher to use
    /// * `nonce` - The nonce
    /// * `counter_pos` - Position of the counter within the counter block
    /// * `counter_size` - Size of the counter in bytes (1-8)
    ///
    /// This allows for flexible counter block layouts to match different standards
    /// and implementations.
    pub fn with_counter_params(
        cipher: B, 
        nonce: &[u8], 
        counter_pos: CounterPosition, 
        counter_size: usize
    ) -> Self {
        let block_size = B::BLOCK_SIZE;
        
        // Validate counter size (1-8 bytes for u64 counter)
        assert!(counter_size > 0 && counter_size <= 8, 
            "Counter size must be between 1 and 8 bytes");
        
        // Determine the counter position
        let position = match counter_pos {
            CounterPosition::Prefix => 0,
            CounterPosition::Postfix => block_size - counter_size,
            CounterPosition::Custom(offset) => {
                assert!(offset + counter_size <= block_size,
                    "Counter with size {} doesn't fit at offset {} in block of size {}",
                    counter_size, offset, block_size);
                offset
            }
        };
        
        // Create and initialize the counter block
        let mut counter_block = vec![0u8; block_size];
        
        // Handle nonce according to its size
        let max_nonce_size = block_size - counter_size;
        
        // If nonce is too large, truncate it
        let effective_nonce = if nonce.len() > max_nonce_size {
            &nonce[0..max_nonce_size]
        } else {
            nonce
        };
        
        // Fill in the nonce
        if position == 0 {
            // Counter is at the beginning, place nonce after it
            counter_block[counter_size..counter_size + effective_nonce.len()].copy_from_slice(effective_nonce);
        } else {
            // Counter is elsewhere, place nonce at the beginning by default
            counter_block[0..effective_nonce.len()].copy_from_slice(effective_nonce);
        }
        
        Self {
            cipher,
            counter_block,
            counter_position: position,
            counter_size,
            keystream: Vec::new(),
            keystream_pos: 0,
        }
    }
    
    /// Generate keystream for CTR mode
    fn generate_keystream(&mut self) {
        let block_size = B::BLOCK_SIZE;
        self.keystream = vec![0u8; block_size];
        
        // Copy current counter block to keystream
        self.keystream.copy_from_slice(&self.counter_block);
        
        // Encrypt the counter value
        self.cipher.encrypt_block(&mut self.keystream);
        
        // Increment the counter based on its size
        self.increment_counter();
        
        self.keystream_pos = 0;
    }
    
    /// Increment the counter in the counter block
    fn increment_counter(&mut self) {
        match self.counter_size {
            8 => {
                let mut counter = [0u8; 8];
                counter.copy_from_slice(&self.counter_block[self.counter_position..self.counter_position + 8]);
                let value = BigEndian::read_u64(&counter);
                BigEndian::write_u64(&mut counter, value.wrapping_add(1));
                self.counter_block[self.counter_position..self.counter_position + 8].copy_from_slice(&counter);
            },
            4 => {
                let mut counter = [0u8; 4];
                counter.copy_from_slice(&self.counter_block[self.counter_position..self.counter_position + 4]);
                let value = BigEndian::read_u32(&counter);
                BigEndian::write_u32(&mut counter, value.wrapping_add(1));
                self.counter_block[self.counter_position..self.counter_position + 4].copy_from_slice(&counter);
            },
            // For other counter sizes, we'll read/write the appropriate number of bytes
            size => {
                let mut value: u64 = 0;
                
                // Read counter value (big-endian)
                for i in 0..size {
                    value = (value << 8) | (self.counter_block[self.counter_position + i] as u64);
                }
                
                // Increment counter
                value = value.wrapping_add(1);
                
                // Write counter value back (big-endian)
                for i in 0..size {
                    self.counter_block[self.counter_position + size - 1 - i] = (value & 0xff) as u8;
                    value >>= 8;
                }
            }
        }
    }
    
    /// Encrypts a message using CTR mode
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        
        for &byte in plaintext {
            if self.keystream_pos >= self.keystream.len() {
                self.generate_keystream();
            }
            
            ciphertext.push(byte ^ self.keystream[self.keystream_pos]);
            self.keystream_pos += 1;
        }
        
        ciphertext
    }
    
    /// Decrypts a message using CTR mode
    /// In CTR mode, encryption and decryption are the same operation
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext)
    }
    
    /// Resets the counter to its initial value plus the given offset
    pub fn reset(&mut self, nonce: &[u8], offset: u64) {
        let max_nonce_size = B::BLOCK_SIZE - self.counter_size;
        assert!(nonce.len() <= max_nonce_size,
            "Nonce size {} exceeds maximum size {} for counter size {}",
            nonce.len(), max_nonce_size, self.counter_size);
        
        // Reset counter block to all zeros
        for i in 0..self.counter_block.len() {
            self.counter_block[i] = 0;
        }
        
        // Fill in the nonce
        if self.counter_position == 0 {
            // Counter is at the beginning, place nonce after it
            self.counter_block[self.counter_size..self.counter_size + nonce.len()].copy_from_slice(nonce);
        } else {
            // Counter is elsewhere, place nonce at the beginning by default
            self.counter_block[0..nonce.len()].copy_from_slice(nonce);
        }
        
        // Set counter to offset value
        match self.counter_size {
            8 => {
                BigEndian::write_u64(&mut self.counter_block[self.counter_position..self.counter_position + 8], offset);
            },
            4 => {
                assert!(offset <= u32::MAX as u64, "Offset too large for 4-byte counter");
                BigEndian::write_u32(&mut self.counter_block[self.counter_position..self.counter_position + 4], offset as u32);
            },
            size => {
                // Make sure offset fits in the counter size
                let max_value = (1u64 << (size * 8)) - 1;
                assert!(offset <= max_value, "Offset too large for {}-byte counter", size);
                
                // Write offset value (big-endian)
                let mut value = offset;
                for i in 0..size {
                    self.counter_block[self.counter_position + size - 1 - i] = (value & 0xff) as u8;
                    value >>= 8;
                }
            }
        }
        
        self.keystream = Vec::new();
        self.keystream_pos = 0;
    }
    
    /// Sets the counter value explicitly
    pub fn set_counter(&mut self, counter_value: u64) {
        // Make sure counter value fits in the counter size
        let max_value = if self.counter_size == 8 {
            u64::MAX
        } else {
            (1u64 << (self.counter_size * 8)) - 1
        };
        
        assert!(counter_value <= max_value, 
            "Counter value too large for {}-byte counter", self.counter_size);
        
        // Write counter value based on its size
        match self.counter_size {
            8 => {
                BigEndian::write_u64(
                    &mut self.counter_block[self.counter_position..self.counter_position + 8], 
                    counter_value
                );
            },
            4 => {
                BigEndian::write_u32(
                    &mut self.counter_block[self.counter_position..self.counter_position + 4], 
                    counter_value as u32
                );
            },
            size => {
                // Write counter value (big-endian)
                let mut value = counter_value;
                for i in 0..size {
                    self.counter_block[self.counter_position + size - 1 - i] = (value & 0xff) as u8;
                    value >>= 8;
                }
            }
        }
        
        // Clear keystream to force regeneration
        self.keystream = Vec::new();
        self.keystream_pos = 0;
    }
}

#[cfg(test)]
mod tests;