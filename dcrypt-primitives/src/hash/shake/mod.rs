//! SHAKE hash functions with fixed output length
//!
//! This module implements the SHAKE family as standard fixed-output hash functions
//! as specified in FIPS PUB 202.
//!
//! For variable-length output, use the XOF implementations in the xof module.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use zeroize::Zeroize;

use super::HashFunction;
use dcrypt_constants::utils::hash::{
    SHA3_224_OUTPUT_SIZE, SHA3_256_OUTPUT_SIZE, SHA3_384_OUTPUT_SIZE, SHA3_512_OUTPUT_SIZE,
    SHA3_256_BLOCK_SIZE, SHA3_512_BLOCK_SIZE
};

// SHAKE constants for fixed output sizes
pub const SHAKE128_OUTPUT_SIZE: usize = 32;  // 256 bits
pub const SHAKE256_OUTPUT_SIZE: usize = 64;  // 512 bits

// SHAKE rates (in bytes): r = 1600 - 2*security_level
const SHAKE128_RATE: usize = 168; // 1600 - 2*128 = 1600 - 256 = 1344 bits = 168 bytes
const SHAKE256_RATE: usize = 136; // 1600 - 2*256 = 1600 - 512 = 1088 bits = 136 bytes

// Keccak constants
const KECCAK_ROUNDS: usize = 24;
const KECCAK_STATE_SIZE: usize = 25; // 5x5 of 64-bit words

// Round constants for Keccak
const RC: [u64; KECCAK_ROUNDS] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

// Rotation offsets
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

// Mapping from index positions to x,y coordinates in the state array
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// SHAKE-128 hash function with fixed output size (32 bytes)
#[derive(Clone, Zeroize)]
pub struct Shake128 {
    state: [u64; KECCAK_STATE_SIZE],
    buffer: [u8; SHAKE128_RATE],
    buffer_idx: usize,
}

/// SHAKE-256 hash function with fixed output size (64 bytes)
#[derive(Clone, Zeroize)]
pub struct Shake256 {
    state: [u64; KECCAK_STATE_SIZE],
    buffer: [u8; SHAKE256_RATE],
    buffer_idx: usize,
}

// Helper functions for Keccak permutation
fn keccak_f1600(state: &mut [u64; KECCAK_STATE_SIZE]) {
    for round in 0..KECCAK_ROUNDS {
        // Theta step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }
        
        // Rho and Pi steps
        let mut b = [0u64; KECCAK_STATE_SIZE];
        let mut x = 1;
        let mut y = 0;
        
        b[0] = state[0];
        
        for i in 0..24 {
            let idx = x + 5 * y;
            b[PI[i]] = state[idx].rotate_left(RHO[i]);
            
            // Update coordinates using formula from Keccak spec
            let temp = y;
            y = (2 * x + 3 * y) % 5;
            x = temp;
        }
        
        // Chi step
        for y in 0..5 {
            for x in 0..5 {
                let idx = x + 5 * y;
                state[idx] = b[idx] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        
        // Iota step - mix in round constant
        state[0] ^= RC[round];
    }
}

impl Shake128 {
    fn init() -> Self {
        Self {
            state: [0u64; KECCAK_STATE_SIZE],
            buffer: [0u8; SHAKE128_RATE],
            buffer_idx: 0,
        }
    }
}

impl HashFunction for Shake128 {
    fn new() -> Self {
        Self::init()
    }
    
    fn update(&mut self, data: &[u8]) {
        let mut idx = 0;
        
        // Fill the buffer if it has some data already
        if self.buffer_idx > 0 {
            let to_copy = std::cmp::min(SHAKE128_RATE - self.buffer_idx, data.len());
            self.buffer[self.buffer_idx..self.buffer_idx + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx = to_copy;
            
            if self.buffer_idx == SHAKE128_RATE {
                // Process the full buffer
                for i in 0..SHAKE128_RATE / 8 {
                    let mut lane = 0u64;
                    for j in 0..8 {
                        lane |= (self.buffer[i * 8 + j] as u64) << (8 * j);
                    }
                    self.state[i] ^= lane;
                }
                
                keccak_f1600(&mut self.state);
                self.buffer_idx = 0;
            }
        }
        
        // Process complete blocks directly from the input data
        let remaining = data.len() - idx;
        let full_blocks = remaining / SHAKE128_RATE;
        
        for i in 0..full_blocks {
            let start = idx + i * SHAKE128_RATE;
            
            // Absorb full block
            for j in 0..SHAKE128_RATE / 8 {
                let mut lane = 0u64;
                for k in 0..8 {
                    let byte_idx = start + j * 8 + k;
                    lane |= (data[byte_idx] as u64) << (8 * k);
                }
                self.state[j] ^= lane;
            }
            
            keccak_f1600(&mut self.state);
        }
        
        idx += full_blocks * SHAKE128_RATE;
        
        // Store any remaining data for next update/finalize
        if idx < data.len() {
            let remaining = data.len() - idx;
            self.buffer[self.buffer_idx..self.buffer_idx + remaining].copy_from_slice(&data[idx..]);
            self.buffer_idx += remaining;
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        // Apply SHAKE padding: 0x1F (SHAKE domain separator) and 0x80 (padding terminator)
        self.buffer[self.buffer_idx] = 0x1F;
        self.buffer_idx += 1;
        
        // Zero out the rest of the buffer except for the last byte
        for i in self.buffer_idx..SHAKE128_RATE - 1 {
            self.buffer[i] = 0;
        }
        
        // Add the final 0x80 byte
        self.buffer[SHAKE128_RATE - 1] = 0x80;
        
        // Absorb the final padded block
        for i in 0..SHAKE128_RATE / 8 {
            let mut lane = 0u64;
            for j in 0..8 {
                lane |= (self.buffer[i * 8 + j] as u64) << (8 * j);
            }
            self.state[i] ^= lane;
        }
        
        keccak_f1600(&mut self.state);
        
        // Squeeze out exactly SHAKE128_OUTPUT_SIZE bytes
        let mut result = vec![0u8; SHAKE128_OUTPUT_SIZE];
        let mut offset = 0;
        
        while offset < SHAKE128_OUTPUT_SIZE {
            let bytes_to_copy = std::cmp::min(SHAKE128_RATE, SHAKE128_OUTPUT_SIZE - offset);
            
            // Extract bytes from state
            for i in 0..bytes_to_copy / 8 + 1 {
                if i * 8 >= bytes_to_copy {
                    break;
                }
                
                let lane = self.state[i];
                let end = std::cmp::min((i + 1) * 8, bytes_to_copy);
                
                for j in 0..end - i * 8 {
                    if offset + i * 8 + j < result.len() {
                        result[offset + i * 8 + j] = ((lane >> (8 * j)) & 0xFF) as u8;
                    }
                }
            }
            
            offset += bytes_to_copy;
            
            // Apply permutation if we need more bytes
            if offset < SHAKE128_OUTPUT_SIZE {
                keccak_f1600(&mut self.state);
            }
        }
        
        result
    }
    
    fn output_size() -> usize {
        SHAKE128_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHAKE128_RATE
    }
    
    fn name() -> &'static str {
        "SHAKE-128"
    }
}

impl Shake256 {
    fn init() -> Self {
        Self {
            state: [0u64; KECCAK_STATE_SIZE],
            buffer: [0u8; SHAKE256_RATE],
            buffer_idx: 0,
        }
    }
}

impl HashFunction for Shake256 {
    fn new() -> Self {
        Self::init()
    }
    
    fn update(&mut self, data: &[u8]) {
        let mut idx = 0;
        
        // Fill the buffer if it has some data already
        if self.buffer_idx > 0 {
            let to_copy = std::cmp::min(SHAKE256_RATE - self.buffer_idx, data.len());
            self.buffer[self.buffer_idx..self.buffer_idx + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx = to_copy;
            
            if self.buffer_idx == SHAKE256_RATE {
                // Process the full buffer
                for i in 0..SHAKE256_RATE / 8 {
                    let mut lane = 0u64;
                    for j in 0..8 {
                        lane |= (self.buffer[i * 8 + j] as u64) << (8 * j);
                    }
                    self.state[i] ^= lane;
                }
                
                keccak_f1600(&mut self.state);
                self.buffer_idx = 0;
            }
        }
        
        // Process complete blocks directly from the input data
        let remaining = data.len() - idx;
        let full_blocks = remaining / SHAKE256_RATE;
        
        for i in 0..full_blocks {
            let start = idx + i * SHAKE256_RATE;
            
            // Absorb full block
            for j in 0..SHAKE256_RATE / 8 {
                let mut lane = 0u64;
                for k in 0..8 {
                    let byte_idx = start + j * 8 + k;
                    lane |= (data[byte_idx] as u64) << (8 * k);
                }
                self.state[j] ^= lane;
            }
            
            keccak_f1600(&mut self.state);
        }
        
        idx += full_blocks * SHAKE256_RATE;
        
        // Store any remaining data for next update/finalize
        if idx < data.len() {
            let remaining = data.len() - idx;
            self.buffer[self.buffer_idx..self.buffer_idx + remaining].copy_from_slice(&data[idx..]);
            self.buffer_idx += remaining;
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        // Apply SHAKE padding: 0x1F (SHAKE domain separator) and 0x80 (padding terminator)
        self.buffer[self.buffer_idx] = 0x1F;
        self.buffer_idx += 1;
        
        // Zero out the rest of the buffer except for the last byte
        for i in self.buffer_idx..SHAKE256_RATE - 1 {
            self.buffer[i] = 0;
        }
        
        // Add the final 0x80 byte
        self.buffer[SHAKE256_RATE - 1] = 0x80;
        
        // Absorb the final padded block
        for i in 0..SHAKE256_RATE / 8 {
            let mut lane = 0u64;
            for j in 0..8 {
                lane |= (self.buffer[i * 8 + j] as u64) << (8 * j);
            }
            self.state[i] ^= lane;
        }
        
        keccak_f1600(&mut self.state);
        
        // Squeeze out exactly SHAKE256_OUTPUT_SIZE bytes
        let mut result = vec![0u8; SHAKE256_OUTPUT_SIZE];
        let mut offset = 0;
        
        while offset < SHAKE256_OUTPUT_SIZE {
            let bytes_to_copy = std::cmp::min(SHAKE256_RATE, SHAKE256_OUTPUT_SIZE - offset);
            
            // Extract bytes from state
            for i in 0..bytes_to_copy / 8 + 1 {
                if i * 8 >= bytes_to_copy {
                    break;
                }
                
                let lane = self.state[i];
                let end = std::cmp::min((i + 1) * 8, bytes_to_copy);
                
                for j in 0..end - i * 8 {
                    if offset + i * 8 + j < result.len() {
                        result[offset + i * 8 + j] = ((lane >> (8 * j)) & 0xFF) as u8;
                    }
                }
            }
            
            offset += bytes_to_copy;
            
            // Apply permutation if we need more bytes
            if offset < SHAKE256_OUTPUT_SIZE {
                keccak_f1600(&mut self.state);
            }
        }
        
        result
    }
    
    fn output_size() -> usize {
        SHAKE256_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHAKE256_RATE
    }
    
    fn name() -> &'static str {
        "SHAKE-256"
    }
}

#[cfg(test)]
mod tests;