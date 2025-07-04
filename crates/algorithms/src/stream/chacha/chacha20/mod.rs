//! ChaCha20 stream cipher implementation
//!
//! This module implements the ChaCha20 stream cipher as defined in RFC 8439.

use byteorder::{ByteOrder, LittleEndian};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::types::Nonce;
use crate::types::nonce::ChaCha20Compatible;
use common::security::{SecretBuffer, EphemeralSecret};

/// Size of ChaCha20 key in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;
/// Size of ChaCha20 nonce in bytes
pub const CHACHA20_NONCE_SIZE: usize = 12;
/// Size of ChaCha20 block in bytes
pub const CHACHA20_BLOCK_SIZE: usize = 64;

/// ChaCha20 stream cipher
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20 {
    /// The key schedule
    state: [u32; 16],
    /// Keystream buffer
    buffer: [u8; CHACHA20_BLOCK_SIZE],
    /// Current position in the buffer
    position: usize,
    /// Current block counter
    counter: u32,
}

impl ChaCha20 {
    /// Creates a new ChaCha20 instance with the specified key and nonce
    pub fn new<const N: usize>(key: &[u8; CHACHA20_KEY_SIZE], nonce: &Nonce<N>) -> Self
    where
        Nonce<N>: ChaCha20Compatible
    {
        // Wrap key in SecretBuffer for secure handling
        let key_buf = SecretBuffer::new(*key);
        Self::with_counter_secure(&key_buf, nonce, 0)
    }
    
    /// Creates a new ChaCha20 instance with the specified key, nonce, and counter
    pub fn with_counter<const N: usize>(key: &[u8; CHACHA20_KEY_SIZE], nonce: &Nonce<N>, counter: u32) -> Self
    where
        Nonce<N>: ChaCha20Compatible
    {
        // Wrap key in SecretBuffer for secure handling
        let key_buf = SecretBuffer::new(*key);
        Self::with_counter_secure(&key_buf, nonce, counter)
    }
    
    /// Internal method that works with SecretBuffer for secure key handling
    fn with_counter_secure<const N: usize>(
        key: &SecretBuffer<CHACHA20_KEY_SIZE>, 
        nonce: &Nonce<N>, 
        counter: u32
    ) -> Self
    where
        Nonce<N>: ChaCha20Compatible
    {
        // Initialize state with constants and key
        let mut state = [0u32; 16];
        
        // "expand 32-byte k" in little-endian
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Key (8 words) - use secure key access
        let key_bytes = key.as_ref();
        for i in 0..8 {
            state[4 + i] = LittleEndian::read_u32(&key_bytes[i * 4..]);
        }
        
        // Counter (1 word)
        state[12] = counter;
        
        // Nonce (3 words)
        let nonce_bytes = nonce.as_ref();
        state[13] = LittleEndian::read_u32(&nonce_bytes[0..4]);
        state[14] = LittleEndian::read_u32(&nonce_bytes[4..8]);
        state[15] = LittleEndian::read_u32(&nonce_bytes[8..12]);
        
        Self {
            state,
            buffer: [0; CHACHA20_BLOCK_SIZE],
            position: CHACHA20_BLOCK_SIZE, // Force initial keystream generation
            counter,
        }
    }
    
    /// Creates from a SecretBuffer key (internal use)
    pub(crate) fn from_secret_key<const N: usize>(
        key: &SecretBuffer<CHACHA20_KEY_SIZE>, 
        nonce: &Nonce<N>
    ) -> Self
    where
        Nonce<N>: ChaCha20Compatible
    {
        Self::with_counter_secure(key, nonce, 0)
    }
    
    /// The ChaCha20 quarter round function
    #[inline]
    fn quarter_round(state: &mut [u32], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);
        
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }
    
    /// Generate a block of keystream
    fn generate_keystream(&mut self) {
        // Create a working copy of the state
        let mut working_state = self.state;
        
        // Ensure the current counter is set in the working state
        working_state[12] = self.counter;
        
        // 20 rounds of ChaCha20: 10 column rounds, 10 diagonal rounds
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working_state, 0, 4, 8, 12);
            Self::quarter_round(&mut working_state, 1, 5, 9, 13);
            Self::quarter_round(&mut working_state, 2, 6, 10, 14);
            Self::quarter_round(&mut working_state, 3, 7, 11, 15);
            
            // Diagonal rounds
            Self::quarter_round(&mut working_state, 0, 5, 10, 15);
            Self::quarter_round(&mut working_state, 1, 6, 11, 12);
            Self::quarter_round(&mut working_state, 2, 7, 8, 13);
            Self::quarter_round(&mut working_state, 3, 4, 9, 14);
        }
        
        // Create output by adding the working state to the original state
        // Use EphemeralSecret to ensure intermediate values are zeroized
        let mut output_state = EphemeralSecret::new([0u32; 16]);
        for i in 0..16 {
            let original_val = if i == 12 { self.counter } else { self.state[i] };
            output_state[i] = working_state[i].wrapping_add(original_val);
        }
        
        // Convert to bytes (little-endian)
        for i in 0..16 {
            LittleEndian::write_u32(&mut self.buffer[i * 4..], output_state[i]);
        }
        
        // Reset position and increment counter for next block
        self.position = 0;
        self.counter = self.counter.wrapping_add(1);
    }
    
    /// Encrypt or decrypt data in place using the ChaCha20 stream cipher
    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            // Generate new keystream block if needed
            if self.position >= CHACHA20_BLOCK_SIZE {
                self.generate_keystream();
            }
            
            // XOR data with keystream
            *byte ^= self.buffer[self.position];
            self.position += 1;
        }
    }
    
    /// Encrypt data in place
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.process(data);
    }
    
    /// Decrypt data in place
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.process(data);
    }
    
    /// Generate keystream directly into an output buffer
    pub fn keystream(&mut self, output: &mut [u8]) {
        // Zero the output buffer
        for byte in output.iter_mut() {
            *byte = 0;
        }

        // Force generation from a block boundary (ignore any leftover position)
        self.position = CHACHA20_BLOCK_SIZE;

        // Then run the encryption pass to copy the keystream
        self.process(output);
    }
    
    /// Seek to a specific block position
    ///
    /// `block_offset` is the number of full blocks that have been consumed;
    /// after seeking, the next generated block will be at `block_offset + 1`.
    pub fn seek(&mut self, block_offset: u32) {
        // Set counter so that generate_keystream() yields the next block
        self.counter = block_offset.wrapping_add(1);

        // Force regeneration on next use
        self.position = CHACHA20_BLOCK_SIZE;

        // Clear any old keystream
        self.buffer.zeroize();
    }
    
    /// Reset to initial state with the same key
    pub fn reset(&mut self) {
        self.counter = self.state[12]; // Restore original counter
        self.position = CHACHA20_BLOCK_SIZE; // Force keystream regeneration
        self.buffer.zeroize(); // Clear keystream buffer
    }
}

#[cfg(test)]
mod tests;