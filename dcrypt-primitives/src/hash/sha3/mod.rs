//! SHA-3 hash function implementations
//!
//! This module implements the SHA-3 family of hash functions as specified in
//! FIPS PUB 202.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::error::Result;
use crate::hash::{Hash, HashFunction, HashAlgorithm};
use crate::types::Digest;

// Import constants
use dcrypt_constants::utils::hash::{
    SHA3_224_OUTPUT_SIZE, SHA3_256_OUTPUT_SIZE, SHA3_384_OUTPUT_SIZE, SHA3_512_OUTPUT_SIZE,
    SHA3_256_BLOCK_SIZE, SHA3_512_BLOCK_SIZE,
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

// Define algorithm marker types for each SHA-3 variant
pub enum Sha3_224Algorithm {}
pub enum Sha3_256Algorithm {}
pub enum Sha3_384Algorithm {}
pub enum Sha3_512Algorithm {}

// Implement HashAlgorithm for each marker type
impl HashAlgorithm for Sha3_224Algorithm {
    const OUTPUT_SIZE: usize = SHA3_224_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA3_224_RATE;
    const ALGORITHM_ID: &'static str = "SHA3-224";
}

impl HashAlgorithm for Sha3_256Algorithm {
    const OUTPUT_SIZE: usize = SHA3_256_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA3_256_RATE;
    const ALGORITHM_ID: &'static str = "SHA3-256";
}

impl HashAlgorithm for Sha3_384Algorithm {
    const OUTPUT_SIZE: usize = SHA3_384_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA3_384_RATE;
    const ALGORITHM_ID: &'static str = "SHA3-384";
}

impl HashAlgorithm for Sha3_512Algorithm {
    const OUTPUT_SIZE: usize = SHA3_512_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA3_512_RATE;
    const ALGORITHM_ID: &'static str = "SHA3-512";
}

// Helper functions for byte-level state access
fn get_byte_from_state(state: &[u64; KECCAK_STATE_SIZE], pos: usize) -> u8 {
    let word_idx = pos / 8;
    let byte_idx = pos % 8;
    ((state[word_idx] >> (8 * byte_idx)) & 0xFF) as u8
}

fn xor_byte_in_state(state: &mut [u64; KECCAK_STATE_SIZE], pos: usize, val: u8) {
    let word_idx = pos / 8;
    let byte_idx = pos % 8;
    state[word_idx] ^= (val as u64) << (8 * byte_idx);
}

/// SHA3-224 hash function
#[derive(Clone, Zeroize)]
pub struct Sha3_224 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
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
    
    fn update_internal(&mut self, data: &[u8]) -> Result<()> {
        let rate = Self::rate();
        for &byte in data {
            xor_byte_in_state(&mut self.state, self.pt, byte);
            self.pt += 1;
            if self.pt == rate {
                keccak_f1600(&mut self.state);
                self.pt = 0;
            }
        }
        Ok(())
    }
    
    fn finalize_internal(&mut self) -> Result<Hash> {
        let rate = Self::rate();
        let out_len = SHA3_224_OUTPUT_SIZE;

        // Padding
        xor_byte_in_state(&mut self.state, self.pt, 0x06);
        xor_byte_in_state(&mut self.state, rate - 1, 0x80);
        keccak_f1600(&mut self.state);

        // Squeeze
        let mut result = vec![0u8; out_len];
        for i in 0..out_len {
            result[i] = get_byte_from_state(&self.state, i);
        }
        self.state = [0u64; KECCAK_STATE_SIZE];
        self.pt = 0;
        Ok(result)
    }
}

/// SHA3-256 hash function
#[derive(Clone, Zeroize)]
pub struct Sha3_256 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
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
    
    fn update_internal(&mut self, data: &[u8]) -> Result<()> {
        let rate = Self::rate();
        for &byte in data {
            xor_byte_in_state(&mut self.state, self.pt, byte);
            self.pt += 1;
            if self.pt == rate {
                keccak_f1600(&mut self.state);
                self.pt = 0;
            }
        }
        Ok(())
    }
    
    fn finalize_internal(&mut self) -> Result<Hash> {
        let rate = Self::rate();
        let out_len = SHA3_256_OUTPUT_SIZE;

        xor_byte_in_state(&mut self.state, self.pt, 0x06);
        xor_byte_in_state(&mut self.state, rate - 1, 0x80);
        keccak_f1600(&mut self.state);

        let mut result = vec![0u8; out_len];
        for i in 0..out_len {
            result[i] = get_byte_from_state(&self.state, i);
        }
        self.state = [0u64; KECCAK_STATE_SIZE];
        self.pt = 0;
        Ok(result)
    }
}

/// SHA3-384 hash function
#[derive(Clone, Zeroize)]
pub struct Sha3_384 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
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
    
    fn update_internal(&mut self, data: &[u8]) -> Result<()> {
        let rate = Self::rate();
        for &byte in data {
            xor_byte_in_state(&mut self.state, self.pt, byte);
            self.pt += 1;
            if self.pt == rate {
                keccak_f1600(&mut self.state);
                self.pt = 0;
            }
        }
        Ok(())
    }
    
    fn finalize_internal(&mut self) -> Result<Hash> {
        let rate = Self::rate();
        let out_len = SHA3_384_OUTPUT_SIZE;

        xor_byte_in_state(&mut self.state, self.pt, 0x06);
        xor_byte_in_state(&mut self.state, rate - 1, 0x80);
        keccak_f1600(&mut self.state);

        let mut result = vec![0u8; out_len];
        for i in 0..out_len {
            result[i] = get_byte_from_state(&self.state, i);
        }
        self.state = [0u64; KECCAK_STATE_SIZE];
        self.pt = 0;
        Ok(result)
    }
}

/// SHA3-512 hash function
#[derive(Clone, Zeroize)]
pub struct Sha3_512 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
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
    
    fn update_internal(&mut self, data: &[u8]) -> Result<()> {
        let rate = Self::rate();
        for &byte in data {
            xor_byte_in_state(&mut self.state, self.pt, byte);
            self.pt += 1;
            if self.pt == rate {
                keccak_f1600(&mut self.state);
                self.pt = 0;
            }
        }
        Ok(())
    }
    
    fn finalize_internal(&mut self) -> Result<Hash> {
        let rate = Self::rate();
        let out_len = SHA3_512_OUTPUT_SIZE;

        xor_byte_in_state(&mut self.state, self.pt, 0x06);
        xor_byte_in_state(&mut self.state, rate - 1, 0x80);
        keccak_f1600(&mut self.state);

        let mut result = vec![0u8; out_len];
        for i in 0..out_len {
            result[i] = get_byte_from_state(&self.state, i);
        }
        self.state = [0u64; KECCAK_STATE_SIZE];
        self.pt = 0;
        Ok(result)
    }
}

// Performs a full Keccak-f[1600] permutation on the state
fn keccak_f1600(state: &mut [u64; KECCAK_STATE_SIZE]) {
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

        // Rho and Pi
        let mut t = state[1];
        for i in 0..24 {
            let j = PI[i];
            let tmp = state[j];
            state[j] = t.rotate_left(RHO[i]);
            t = tmp;
        }

        // Chi
        for y in 0..5 {
            let mut row = [0u64; 5];
            for x in 0..5 {
                row[x] = state[x + 5 * y];
            }
            for x in 0..5 {
                state[x + 5 * y] ^= (!row[(x + 1) % 5]) & row[(x + 2) % 5];
            }
        }

        // Iota
        state[0] ^= RC[round];
    }
}

// Implement HashFunction for each SHA-3 variant
impl HashFunction for Sha3_224 {
    type Algorithm = Sha3_224Algorithm;
    type Output = Digest<SHA3_224_OUTPUT_SIZE>;

    fn new() -> Self {
        Self::init()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = [0u8; SHA3_224_OUTPUT_SIZE];
        digest.copy_from_slice(&hash);
        Ok(Digest::new(digest))
    }

    fn output_size() -> usize {
        Self::Algorithm::OUTPUT_SIZE
    }

    fn block_size() -> usize {
        Self::Algorithm::BLOCK_SIZE
    }

    fn name() -> String {
        Self::Algorithm::ALGORITHM_ID.to_string()
    }
}

impl HashFunction for Sha3_256 {
    type Algorithm = Sha3_256Algorithm;
    type Output = Digest<SHA3_256_OUTPUT_SIZE>;

    fn new() -> Self {
        Self::init()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = [0u8; SHA3_256_OUTPUT_SIZE];
        digest.copy_from_slice(&hash);
        Ok(Digest::new(digest))
    }

    fn output_size() -> usize {
        Self::Algorithm::OUTPUT_SIZE
    }

    fn block_size() -> usize {
        Self::Algorithm::BLOCK_SIZE
    }

    fn name() -> String {
        Self::Algorithm::ALGORITHM_ID.to_string()
    }
}

impl HashFunction for Sha3_384 {
    type Algorithm = Sha3_384Algorithm;
    type Output = Digest<SHA3_384_OUTPUT_SIZE>;

    fn new() -> Self {
        Self::init()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = [0u8; SHA3_384_OUTPUT_SIZE];
        digest.copy_from_slice(&hash);
        Ok(Digest::new(digest))
    }

    fn output_size() -> usize {
        Self::Algorithm::OUTPUT_SIZE
    }

    fn block_size() -> usize {
        Self::Algorithm::BLOCK_SIZE
    }

    fn name() -> String {
        Self::Algorithm::ALGORITHM_ID.to_string()
    }
}

impl HashFunction for Sha3_512 {
    type Algorithm = Sha3_512Algorithm;
    type Output = Digest<SHA3_512_OUTPUT_SIZE>;

    fn new() -> Self {
        Self::init()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = [0u8; SHA3_512_OUTPUT_SIZE];
        digest.copy_from_slice(&hash);
        Ok(Digest::new(digest))
    }

    fn output_size() -> usize {
        Self::Algorithm::OUTPUT_SIZE
    }

    fn block_size() -> usize {
        Self::Algorithm::BLOCK_SIZE
    }

    fn name() -> String {
        Self::Algorithm::ALGORITHM_ID.to_string()
    }
}

#[cfg(test)]
mod tests;