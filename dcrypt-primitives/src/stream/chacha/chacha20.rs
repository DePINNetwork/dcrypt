//! ChaCha20 stream cipher implementation
//!
//! This module implements the ChaCha20 stream cipher as defined in RFC 8439.

use crate::error::{Error, Result};
use byteorder::{ByteOrder, LittleEndian};
use zeroize::Zeroize;

/// Size of ChaCha20 key in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;
/// Size of ChaCha20 nonce in bytes
pub const CHACHA20_NONCE_SIZE: usize = 12;
/// Size of ChaCha20 block in bytes
pub const CHACHA20_BLOCK_SIZE: usize = 64;

/// ChaCha20 stream cipher
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
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
    pub fn new(key: &[u8; CHACHA20_KEY_SIZE], nonce: &[u8; CHACHA20_NONCE_SIZE]) -> Self {
        Self::with_counter(key, nonce, 0)
    }
    
    /// Creates a new ChaCha20 instance with the specified key, nonce, and counter
    pub fn with_counter(key: &[u8; CHACHA20_KEY_SIZE], nonce: &[u8; CHACHA20_NONCE_SIZE], counter: u32) -> Self {
        // Initialize state with constants and key
        let mut state = [0u32; 16];
        
        // "expand 32-byte k" in little-endian
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Key (8 words)
        for i in 0..8 {
            state[4 + i] = LittleEndian::read_u32(&key[i * 4..]);
        }
        
        // Counter (1 word)
        state[12] = counter;
        
        // Nonce (3 words)
        state[13] = LittleEndian::read_u32(&nonce[0..4]);
        state[14] = LittleEndian::read_u32(&nonce[4..8]);
        state[15] = LittleEndian::read_u32(&nonce[8..12]);
        
        Self {
            state,
            buffer: [0; CHACHA20_BLOCK_SIZE],
            position: CHACHA20_BLOCK_SIZE, // Force initial keystream generation
            counter,
        }
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
        // But use the current counter value for position 12
        let mut output_state = [0u32; 16];
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
        self.buffer = [0; CHACHA20_BLOCK_SIZE];
    }
    
    /// Reset to initial state with the same key
    pub fn reset(&mut self) {
        self.counter = self.state[12]; // Restore original counter
        self.position = CHACHA20_BLOCK_SIZE; // Force keystream regeneration
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    
    #[test]
    fn test_chacha20_rfc8439() {
        // Test vector from RFC 8439
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let nonce = hex::decode("000000000000004a00000000")
            .unwrap();
        let plaintext = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
            .unwrap();
        let expected_ciphertext = hex::decode("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d")
            .unwrap();
        
        // Convert to proper types
        let key_bytes: [u8; CHACHA20_KEY_SIZE] = key.try_into().expect("Invalid key length");
        let nonce_bytes: [u8; CHACHA20_NONCE_SIZE] = nonce.try_into().expect("Invalid nonce length");
        
        // Create cipher with counter=1
        let mut chacha = ChaCha20::with_counter(&key_bytes, &nonce_bytes, 1);
        
        // Encrypt
        let mut output = plaintext.clone();
        chacha.encrypt(&mut output);
        
        assert_eq!(output, expected_ciphertext);
        
        // Test decryption
        let mut chacha = ChaCha20::with_counter(&key_bytes, &nonce_bytes, 1);
        let mut decrypted = expected_ciphertext.clone();
        chacha.decrypt(&mut decrypted);
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_chacha20_keystream() {
        // Test with a sample key and nonce
        let key = [0x42; CHACHA20_KEY_SIZE];
        let nonce = [0x24; CHACHA20_NONCE_SIZE];
        
        let mut chacha = ChaCha20::new(&key, &nonce);
        
        // Generate keystream and test encryption
        let mut keystream = [0u8; 64];
        chacha.keystream(&mut keystream);
        
        let plaintext = [0x12; 64];
        let mut ciphertext = plaintext;
        
        // Reset to start
        chacha.reset();
        chacha.encrypt(&mut ciphertext);
        
        // Manual XOR to verify
        let mut expected = [0u8; 64];
        for i in 0..64 {
            expected[i] = plaintext[i] ^ keystream[i];
        }
        
        assert_eq!(ciphertext, expected);
    }
    
    #[test]
    fn test_chacha20_seek() {
        // Test seeking to a specific counter
        let key = [0x42; CHACHA20_KEY_SIZE];
        let nonce = [0x24; CHACHA20_NONCE_SIZE];
        
        // Create two ciphers
        let mut chacha1 = ChaCha20::new(&key, &nonce);
        let mut chacha2 = ChaCha20::new(&key, &nonce);
        
        // Advance chacha1 by processing some data
        let mut data = [0u8; 200];
        chacha1.process(&mut data);
        
        // Seek chacha2 to where chacha1 should be
        chacha2.seek(3); // After 200 bytes (3 full blocks + part of 4th)
        
        // Both should now produce the same keystream
        let mut ks1 = [0u8; 64];
        let mut ks2 = [0u8; 64];
        
        chacha1.keystream(&mut ks1);
        chacha2.keystream(&mut ks2);
        
        assert_eq!(ks1, ks2);
    }
}