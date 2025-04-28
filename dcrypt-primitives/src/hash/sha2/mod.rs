//! SHA-2 hash function implementations
//!
//! This module implements the SHA-2 family of hash functions as specified in
//! FIPS PUB 180-4.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use zeroize::Zeroize;

use super::HashFunction;

use dcrypt_constants::utils::hash::{
    SHA224_OUTPUT_SIZE, SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, SHA512_OUTPUT_SIZE,
    SHA256_BLOCK_SIZE, SHA512_BLOCK_SIZE
};

// SHA-256 round constants
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

// SHA-512 round constants
const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

/// SHA-224 hash function
#[derive(Clone, Zeroize)]
pub struct Sha224 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u64,
}

/// SHA-256 hash function
#[derive(Clone, Zeroize)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u64,
}

/// SHA-384 hash function
#[derive(Clone, Zeroize)]
pub struct Sha384 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u128,
}

/// SHA-512 hash function
#[derive(Clone, Zeroize)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u128,
}

// SHA-256 implementation

impl Sha256 {
    /// Initialize SHA-256 state with the standard initial values
    fn init_state() -> [u32; 8] {
        [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
    }
    
    /// Process a single block (64 bytes) of data
    fn process_block(&mut self, block: &[u8; SHA256_BLOCK_SIZE]) {
        Self::compress(&mut self.state, block);
    }
    
    /// SHA-256 compression function
    fn compress(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_SIZE]) {
        let mut w = [0u32; 64];
        
        // Prepare the message schedule
        for i in 0..16 {
            w[i] = BigEndian::read_u32(&block[i * 4..]);
        }
        
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        
        // Initialize working variables
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        
        // Main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        
        // Update state
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

impl HashFunction for Sha256 {
    fn new() -> Self {
        Sha256 {
            state: Self::init_state(),
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        let mut idx = 0;
        self.total_bytes += data.len() as u64;
        
        // Fill the buffer if it has some data already
        if self.buffer_idx > 0 {
            let to_copy = (SHA256_BLOCK_SIZE - self.buffer_idx).min(data.len());
            self.buffer[self.buffer_idx..self.buffer_idx + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx = to_copy;
            
            if self.buffer_idx == SHA256_BLOCK_SIZE {
                Self::compress(&mut self.state, &self.buffer);
                self.buffer_idx = 0;
            }
        }
        
        // Process complete blocks directly from the input data
        while idx + SHA256_BLOCK_SIZE <= data.len() {
            // Create a temporary block array to pass to compress
            let mut block = [0u8; SHA256_BLOCK_SIZE];
            block.copy_from_slice(&data[idx..idx + SHA256_BLOCK_SIZE]);
            Self::compress(&mut self.state, &block);
            idx += SHA256_BLOCK_SIZE;
        }
        
        // Store any remaining data for next update/finalize
        if idx < data.len() {
            let remaining = data.len() - idx;
            self.buffer[self.buffer_idx..self.buffer_idx + remaining].copy_from_slice(&data[idx..]);
            self.buffer_idx += remaining;
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        // Add padding
        let bit_len = self.total_bytes * 8;
        let idx = self.buffer_idx;
        
        // Add the first byte of padding: 0x80
        self.buffer[idx] = 0x80;
        
        // If there's not enough space for the length (need 8 bytes), process this block
        // and prepare a new one
        if idx >= 56 {
            // Fill with zeros up to the end of the block
            for i in idx + 1..SHA256_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            
            // Process the current block
            Self::compress(&mut self.state, &self.buffer);
            
            // Prepare a new block with zeros for the length
            self.buffer = [0u8; SHA256_BLOCK_SIZE];
        } else {
            // Fill with zeros up to where we'll put the length
            for i in idx + 1..56 {
                self.buffer[i] = 0;
            }
        }
        
        // Append the length in bits (big endian)
        BigEndian::write_u64(&mut self.buffer[56..], bit_len);
        
        // Process the final block
        Self::compress(&mut self.state, &self.buffer);
        
        // Build the result by converting state to bytes
        let mut result = Vec::with_capacity(SHA256_OUTPUT_SIZE);
        for &word in &self.state[0..8] {
            result.extend_from_slice(&word.to_be_bytes());
        }
        
        // Zero sensitive data
        self.zeroize();
        
        result
    }
    
    fn output_size() -> usize {
        SHA256_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHA256_BLOCK_SIZE
    }
    
    fn name() -> &'static str {
        "SHA-256"
    }
}

// SHA-224 implementation (based on SHA-256)

impl Sha224 {
    /// Initialize SHA-224 state with the standard initial values
    fn init_state() -> [u32; 8] {
        [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ]
    }
    
    /// Process a single block (64 bytes) of data
    fn process_block(&mut self, block: &[u8; SHA256_BLOCK_SIZE]) {
        Sha256::compress(&mut self.state, block);
    }
}

impl HashFunction for Sha224 {
    fn new() -> Self {
        Sha224 {
            state: Self::init_state(),
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        let mut idx = 0;
        self.total_bytes += data.len() as u64;
        
        // Fill the buffer if it has some data already
        if self.buffer_idx > 0 {
            let to_copy = (SHA256_BLOCK_SIZE - self.buffer_idx).min(data.len());
            self.buffer[self.buffer_idx..self.buffer_idx + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx = to_copy;
            
            if self.buffer_idx == SHA256_BLOCK_SIZE {
                Sha256::compress(&mut self.state, &self.buffer);
                self.buffer_idx = 0;
            }
        }
        
        // Process complete blocks directly from the input data
        while idx + SHA256_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA256_BLOCK_SIZE];
            block.copy_from_slice(&data[idx..idx + SHA256_BLOCK_SIZE]);
            Sha256::compress(&mut self.state, &block);
            idx += SHA256_BLOCK_SIZE;
        }
        
        // Store any remaining data for next update/finalize
        if idx < data.len() {
            let remaining = data.len() - idx;
            self.buffer[self.buffer_idx..self.buffer_idx + remaining].copy_from_slice(&data[idx..]);
            self.buffer_idx += remaining;
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        // Add padding
        let bit_len = self.total_bytes * 8;
        let idx = self.buffer_idx;
        
        // Add the first byte of padding: 0x80
        self.buffer[idx] = 0x80;
        
        // If there's not enough space for the length (need 8 bytes), process this block
        // and prepare a new one
        if idx >= 56 {
            // Fill with zeros up to the end of the block
            for i in idx + 1..SHA256_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            
            Sha256::compress(&mut self.state, &self.buffer);
            
            // Prepare a new block with zeros for the length
            self.buffer = [0u8; SHA256_BLOCK_SIZE];
        } else {
            // Fill with zeros up to where we'll put the length
            for i in idx + 1..56 {
                self.buffer[i] = 0;
            }
        }
        
        // Append the length in bits (big endian)
        BigEndian::write_u64(&mut self.buffer[56..], bit_len);
        
        // Process the final block
        Sha256::compress(&mut self.state, &self.buffer);
        
        // Build the result by converting state to bytes
        // For SHA-224, we only take the first 7 words (224 bits)
        let mut result = Vec::with_capacity(SHA224_OUTPUT_SIZE);
        for &word in &self.state[0..7] {
            result.extend_from_slice(&word.to_be_bytes());
        }
        
        // Zero sensitive data
        self.zeroize();
        
        result
    }
    
    fn output_size() -> usize {
        SHA224_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHA256_BLOCK_SIZE
    }
    
    fn name() -> &'static str {
        "SHA-224"
    }
}

// SHA-512 implementation

impl Sha512 {
    /// Initialize SHA-512 state with the standard initial values
    fn init_state() -> [u64; 8] {
        [
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
        ]
    }
    
    /// Process a single block (128 bytes) of data
    fn process_block(&mut self, block: &[u8; SHA512_BLOCK_SIZE]) {
        Self::compress(&mut self.state, block);
    }
    
    /// SHA-512 compression function
    fn compress(state: &mut [u64; 8], block: &[u8; SHA512_BLOCK_SIZE]) {
        let mut w = [0u64; 80];
        
        // Prepare the message schedule
        for i in 0..16 {
            w[i] = BigEndian::read_u64(&block[i * 8..]);
        }
        
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        
        // Initialize working variables
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        
        // Main loop
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        
        // Update state
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

impl HashFunction for Sha512 {
    fn new() -> Self {
        Sha512 {
            state: Self::init_state(),
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        let mut idx = 0;
        self.total_bytes += data.len() as u128;
        
        // Fill the buffer if it has some data already
        if self.buffer_idx > 0 {
            let to_copy = (SHA512_BLOCK_SIZE - self.buffer_idx).min(data.len());
            self.buffer[self.buffer_idx..self.buffer_idx + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx = to_copy;
            
            if self.buffer_idx == SHA512_BLOCK_SIZE {
                Self::compress(&mut self.state, &self.buffer);
                self.buffer_idx = 0;
            }
        }
        
        // Process complete blocks directly from the input data
        while idx + SHA512_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA512_BLOCK_SIZE];
            block.copy_from_slice(&data[idx..idx + SHA512_BLOCK_SIZE]);
            Self::compress(&mut self.state, &block);
            idx += SHA512_BLOCK_SIZE;
        }
        
        // Store any remaining data for next update/finalize
        if idx < data.len() {
            let remaining = data.len() - idx;
            self.buffer[self.buffer_idx..self.buffer_idx + remaining].copy_from_slice(&data[idx..]);
            self.buffer_idx += remaining;
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        // Add padding
        let bit_len = self.total_bytes * 8;
        let idx = self.buffer_idx;
        
        // Add the first byte of padding: 0x80
        self.buffer[idx] = 0x80;
        
        // If there's not enough space for the length (need 16 bytes), process this block
        // and prepare a new one
        if idx >= 112 {
            // Fill with zeros up to the end of the block
            for i in idx + 1..SHA512_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            
            Self::compress(&mut self.state, &self.buffer);
            
            // Prepare a new block with zeros for the length
            self.buffer = [0u8; SHA512_BLOCK_SIZE];
        } else {
            // Fill with zeros up to where we'll put the length
            for i in idx + 1..112 {
                self.buffer[i] = 0;
            }
        }
        
        // Append the length in bits (big endian) - for SHA-512, we use 16 bytes (128 bits)
        // First 8 bytes are typically 0 for most practical cases
        BigEndian::write_u64(&mut self.buffer[112..120], 0);
        BigEndian::write_u64(&mut self.buffer[120..128], bit_len as u64);
        
        // Process the final block
        Self::compress(&mut self.state, &self.buffer);
        
        // Build the result by converting state to bytes
        let mut result = Vec::with_capacity(SHA512_OUTPUT_SIZE);
        for &word in &self.state[0..8] {
            result.extend_from_slice(&word.to_be_bytes());
        }
        
        // Zero sensitive data
        self.zeroize();
        
        result
    }
    
    fn output_size() -> usize {
        SHA512_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHA512_BLOCK_SIZE
    }
    
    fn name() -> &'static str {
        "SHA-512"
    }
}

// SHA-384 implementation (based on SHA-512)

impl Sha384 {
    /// Initialize SHA-384 state with the standard initial values
    fn init_state() -> [u64; 8] {
        [
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
        ]
    }
    
    /// Process a single block (128 bytes) of data
    fn process_block(&mut self, block: &[u8; SHA512_BLOCK_SIZE]) {
        Sha512::compress(&mut self.state, block);
    }
}

impl HashFunction for Sha384 {
    fn new() -> Self {
        Sha384 {
            state: Self::init_state(),
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        let mut idx = 0;
        self.total_bytes += data.len() as u128;
        
        // Fill the buffer if it has some data already
        if self.buffer_idx > 0 {
            let to_copy = (SHA512_BLOCK_SIZE - self.buffer_idx).min(data.len());
            self.buffer[self.buffer_idx..self.buffer_idx + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx = to_copy;
            
            if self.buffer_idx == SHA512_BLOCK_SIZE {
                Sha512::compress(&mut self.state, &self.buffer);
                self.buffer_idx = 0;
            }
        }
        
        // Process complete blocks directly from the input data
        while idx + SHA512_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA512_BLOCK_SIZE];
            block.copy_from_slice(&data[idx..idx + SHA512_BLOCK_SIZE]);
            Sha512::compress(&mut self.state, &block);
            idx += SHA512_BLOCK_SIZE;
        }
        
        // Store any remaining data for next update/finalize
        if idx < data.len() {
            let remaining = data.len() - idx;
            self.buffer[self.buffer_idx..self.buffer_idx + remaining].copy_from_slice(&data[idx..]);
            self.buffer_idx += remaining;
        }
    }
    
    fn finalize(&mut self) -> Vec<u8> {
        // Process similarly to SHA-512, but only output first 48 bytes
        // Add padding
        let bit_len = self.total_bytes * 8;
        let idx = self.buffer_idx;
        
        // Add the first byte of padding: 0x80
        self.buffer[idx] = 0x80;
        
        // If there's not enough space for the length (need 16 bytes), process this block
        // and prepare a new one
        if idx >= 112 {
            // Fill with zeros up to the end of the block
            for i in idx + 1..SHA512_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            
            Sha512::compress(&mut self.state, &self.buffer);
            
            // Prepare a new block with zeros for the length
            self.buffer = [0u8; SHA512_BLOCK_SIZE];
        } else {
            // Fill with zeros up to where we'll put the length
            for i in idx + 1..112 {
                self.buffer[i] = 0;
            }
        }
        
        // Append the length in bits (big endian)
        BigEndian::write_u64(&mut self.buffer[112..120], 0);
        BigEndian::write_u64(&mut self.buffer[120..128], bit_len as u64);
        
        // Process the final block
        Sha512::compress(&mut self.state, &self.buffer);
        
        // Build the result by converting state to bytes
        // For SHA-384, we only take the first 6 words (384 bits)
        let mut result = Vec::with_capacity(SHA384_OUTPUT_SIZE);
        for &word in &self.state[0..6] {
            result.extend_from_slice(&word.to_be_bytes());
        }
        
        // Zero sensitive data
        self.zeroize();
        
        result
    }
    
    fn output_size() -> usize {
        SHA384_OUTPUT_SIZE
    }
    
    fn block_size() -> usize {
        SHA512_BLOCK_SIZE
    }
    
    fn name() -> &'static str {
        "SHA-384"
    }
}

#[cfg(test)]
mod tests;