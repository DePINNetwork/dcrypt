//! SHA-3 hash function implementations
//!
//! This module implements the SHA-3 family of hash functions as specified in
//! FIPS PUB 202.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use zeroize::Zeroize;

use super::HashFunction;
use dcrypt_constants::utils::hash::{
    SHA3_224_OUTPUT_SIZE, SHA3_256_OUTPUT_SIZE, SHA3_384_OUTPUT_SIZE, SHA3_512_OUTPUT_SIZE,
    SHA3_256_BLOCK_SIZE, SHA3_512_BLOCK_SIZE
};

// Keccak constants
const KECCAK_ROUNDS: usize = 24;
const KECCAK_STATE_SIZE: usize = 25; // 5x5 of 64-bit words

// SHA-3 rates (in bytes)
const SHA3_224_RATE: usize = 144; // 1600 - 2*224 = 1152 bits = 144 bytes
const SHA3_256_RATE: usize = 136; // 1600 - 2*256 = 1088 bits = 136 bytes
const SHA3_384_RATE: usize = 104; // 1600 - 2*384 = 832 bits = 104 bytes
const SHA3_512_RATE: usize = 72;  // 1600 - 2*512 = 576 bits = 72 bytes

// Round constants for SHA-3
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

/// SHA3-224 hash function
#[derive(Clone, Zeroize)]
pub struct Sha3_224 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize, // Position tracker (pt) as in the reference implementation
}

/// SHA3-256 hash function
#[derive(Clone, Zeroize)]
pub struct Sha3_256 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
}

/// SHA3-384 hash function
#[derive(Clone, Zeroize)]
pub struct Sha3_384 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
}

/// SHA3-512 hash function
#[derive(Clone, Zeroize)]
pub struct Sha3_512 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
}

/// Performs a full Keccak-f[1600] permutation on the state
fn keccak_f1600(state: &mut [u64; KECCAK_STATE_SIZE]) {
    // Keccak-f permutation
    for round in 0..KECCAK_ROUNDS {
        // Theta
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }

        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in 0..5 {
                state[i + 5 * j] ^= t;
            }
        }

        // Rho Pi
        let mut t = state[1];
        for i in 0..24 {
            let j = PI[i];
            let bc0 = state[j];
            state[j] = t.rotate_left(RHO[i]);
            t = bc0;
        }

        // Chi
        for j in 0..5 {
            let mut bc = [0u64; 5];
            for i in 0..5 {
                bc[i] = state[i + 5 * j];
            }
            for i in 0..5 {
                state[i + 5 * j] ^= (!bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        state[0] ^= RC[round];
    }
}

// Helper function to get a byte from a state array
fn get_byte_from_state(state: &[u64; KECCAK_STATE_SIZE], pos: usize) -> u8 {
    let word_idx = pos / 8;
    let byte_idx = pos % 8;
    ((state[word_idx] >> (8 * byte_idx)) & 0xFF) as u8
}

// Helper function to set a byte in a state array
fn set_byte_in_state(state: &mut [u64; KECCAK_STATE_SIZE], pos: usize, val: u8) {
    let word_idx = pos / 8;
    let byte_idx = pos % 8;
    let mask = !(0xFFu64 << (8 * byte_idx));
    state[word_idx] = (state[word_idx] & mask) | ((val as u64) << (8 * byte_idx));
}

// Helper function to XOR a byte into a state array
fn xor_byte_in_state(state: &mut [u64; KECCAK_STATE_SIZE], pos: usize, val: u8) {
    let word_idx = pos / 8;
    let byte_idx = pos % 8;
    state[word_idx] ^= (val as u64) << (8 * byte_idx);
}

impl Sha3_256 {
    fn init() -> Self {
        Sha3_256 {
            state: [0u64; KECCAK_STATE_SIZE],
            pt: 0,
        }
    }
    
    fn rate() -> usize {
        SHA3_256_RATE
    }
}

impl HashFunction for Sha3_256 {
    fn new() -> Self {
        Self::init()
    }
    
    fn update(&mut self, data: &[u8]) {
        let rate = Self::rate();
        
        for &byte in data {
            xor_byte_in_state(&mut self.state, self.pt, byte);
            self.pt += 1;
            
            if self.pt == rate {
                keccak_f1600(&mut self.state);
                self.pt = 0;
            }
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        let rate = Self::rate();
        let output_size = Self::output_size();
        
        // Add domain separator (0x06) and padding (0x80)
        xor_byte_in_state(&mut self.state, self.pt, 0x06);
        xor_byte_in_state(&mut self.state, rate - 1, 0x80);
        
        // Apply permutation
        keccak_f1600(&mut self.state);
        
        // Extract output
        let mut result = vec![0u8; output_size];
        for i in 0..output_size {
            result[i] = get_byte_from_state(&self.state, i);
        }
        
        // Reset state
        self.state = [0u64; KECCAK_STATE_SIZE];
        self.pt = 0;
        
        result
    }
    
    fn output_size() -> usize {
        SHA3_256_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHA3_256_BLOCK_SIZE
    }
    
    fn name() -> &'static str {
        "SHA3-256"
    }
}

impl Sha3_224 {
    fn init() -> Self {
        Sha3_224 {
            state: [0u64; KECCAK_STATE_SIZE],
            pt: 0,
        }
    }
    
    fn rate() -> usize {
        SHA3_224_RATE
    }
}

impl HashFunction for Sha3_224 {
    fn new() -> Self {
        Self::init()
    }
    
    fn update(&mut self, data: &[u8]) {
        let rate = Self::rate();
        
        for &byte in data {
            xor_byte_in_state(&mut self.state, self.pt, byte);
            self.pt += 1;
            
            if self.pt == rate {
                keccak_f1600(&mut self.state);
                self.pt = 0;
            }
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        let rate = Self::rate();
        let output_size = Self::output_size();
        
        // Add domain separator (0x06) and padding (0x80)
        xor_byte_in_state(&mut self.state, self.pt, 0x06);
        xor_byte_in_state(&mut self.state, rate - 1, 0x80);
        
        // Apply permutation
        keccak_f1600(&mut self.state);
        
        // Extract output
        let mut result = vec![0u8; output_size];
        for i in 0..output_size {
            result[i] = get_byte_from_state(&self.state, i);
        }
        
        // Reset state
        self.state = [0u64; KECCAK_STATE_SIZE];
        self.pt = 0;
        
        result
    }
    
    fn output_size() -> usize {
        SHA3_224_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHA3_256_BLOCK_SIZE
    }
    
    fn name() -> &'static str {
        "SHA3-224"
    }
}

impl Sha3_384 {
    fn init() -> Self {
        Sha3_384 {
            state: [0u64; KECCAK_STATE_SIZE],
            pt: 0,
        }
    }
    
    fn rate() -> usize {
        SHA3_384_RATE
    }
}

impl HashFunction for Sha3_384 {
    fn new() -> Self {
        Self::init()
    }
    
    fn update(&mut self, data: &[u8]) {
        let rate = Self::rate();
        
        for &byte in data {
            xor_byte_in_state(&mut self.state, self.pt, byte);
            self.pt += 1;
            
            if self.pt == rate {
                keccak_f1600(&mut self.state);
                self.pt = 0;
            }
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        let rate = Self::rate();
        let output_size = Self::output_size();
        
        // Add domain separator (0x06) and padding (0x80)
        xor_byte_in_state(&mut self.state, self.pt, 0x06);
        xor_byte_in_state(&mut self.state, rate - 1, 0x80);
        
        // Apply permutation
        keccak_f1600(&mut self.state);
        
        // Extract output
        let mut result = vec![0u8; output_size];
        for i in 0..output_size {
            result[i] = get_byte_from_state(&self.state, i);
        }
        
        // Reset state
        self.state = [0u64; KECCAK_STATE_SIZE];
        self.pt = 0;
        
        result
    }
    
    fn output_size() -> usize {
        SHA3_384_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHA3_512_BLOCK_SIZE
    }
    
    fn name() -> &'static str {
        "SHA3-384"
    }
}

impl Sha3_512 {
    fn init() -> Self {
        Sha3_512 {
            state: [0u64; KECCAK_STATE_SIZE],
            pt: 0,
        }
    }
    
    fn rate() -> usize {
        SHA3_512_RATE
    }
}

impl HashFunction for Sha3_512 {
    fn new() -> Self {
        Self::init()
    }
    
    fn update(&mut self, data: &[u8]) {
        let rate = Self::rate();
        
        for &byte in data {
            xor_byte_in_state(&mut self.state, self.pt, byte);
            self.pt += 1;
            
            if self.pt == rate {
                keccak_f1600(&mut self.state);
                self.pt = 0;
            }
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        let rate = Self::rate();
        let output_size = Self::output_size();
        
        // Add domain separator (0x06) and padding (0x80)
        xor_byte_in_state(&mut self.state, self.pt, 0x06);
        xor_byte_in_state(&mut self.state, rate - 1, 0x80);
        
        // Apply permutation
        keccak_f1600(&mut self.state);
        
        // Extract output
        let mut result = vec![0u8; output_size];
        for i in 0..output_size {
            result[i] = get_byte_from_state(&self.state, i);
        }
        
        // Reset state
        self.state = [0u64; KECCAK_STATE_SIZE];
        self.pt = 0;
        
        result
    }
    
    fn output_size() -> usize {
        SHA3_512_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHA3_512_BLOCK_SIZE
    }
    
    fn name() -> &'static str {
        "SHA3-512"
    }
}

#[cfg(test)]
mod tests;