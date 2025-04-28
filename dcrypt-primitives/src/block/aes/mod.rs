//! AES block cipher implementations
//!
//! This module implements the Advanced Encryption Standard (AES) block cipher
//! as specified in FIPS 197.

use zeroize::Zeroize;
use core::convert::TryInto;
use super::BlockCipher;
use dcrypt_constants::utils::symmetric::{AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, AES_BLOCK_SIZE};

// AES S-box lookup table
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// AES inverse S-box lookup table
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// Round constants for AES key expansion
const RCON: [u32; 11] = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
];

/// AES-128 block cipher
#[derive(Clone, Zeroize)]
pub struct Aes128 {
    round_keys: [u32; 44],
}

/// AES-192 block cipher
#[derive(Clone, Zeroize)]
pub struct Aes192 {
    round_keys: [u32; 52],
}

/// AES-256 block cipher
#[derive(Clone, Zeroize)]
pub struct Aes256 {
    round_keys: [u32; 60],
}

// AES helper functions

/// Converts 4 bytes to a u32 in big-endian order
fn bytes_to_u32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 24) |
    ((bytes[1] as u32) << 16) |
    ((bytes[2] as u32) << 8) |
    (bytes[3] as u32)
}

/// Converts a u32 to 4 bytes in big-endian order
fn u32_to_bytes(word: u32) -> [u8; 4] {
    [
        (word >> 24) as u8,
        (word >> 16) as u8,
        (word >> 8) as u8,
        word as u8,
    ]
}

/// Rotates a word left by 8 bits (1 byte)
fn rotate_word(word: u32) -> u32 {
    (word << 8) | (word >> 24)
}

/// Substitutes each byte in a word using the AES S-box
fn sub_word(word: u32) -> u32 {
    let bytes = u32_to_bytes(word);
    let sub_bytes = [
        SBOX[bytes[0] as usize],
        SBOX[bytes[1] as usize],
        SBOX[bytes[2] as usize],
        SBOX[bytes[3] as usize],
    ];
    bytes_to_u32(&sub_bytes)
}

/// AES implementation for AES-128

impl Aes128 {
    /// Performs AES-128 key expansion
    fn expand_key(key: &[u8]) -> [u32; 44] {
        assert_eq!(key.len(), AES128_KEY_SIZE);
        
        let mut round_keys = [0u32; 44];
        
        // First round key is the original key
        for i in 0..4 {
            round_keys[i] = bytes_to_u32(&key[i * 4..(i + 1) * 4]);
        }
        
        // Generate additional round keys
        for i in 4..44 {
            let mut temp = round_keys[i - 1];
            
            if i % 4 == 0 {
                temp = sub_word(rotate_word(temp)) ^ RCON[i / 4];
            }
            
            round_keys[i] = round_keys[i - 4] ^ temp;
        }
        
        round_keys
    }
    
    /// Performs the AES SubBytes step
    fn sub_bytes(state: &mut [u8; 16]) {
        for i in 0..16 {
            state[i] = SBOX[state[i] as usize];
        }
    }
    
    /// Performs the AES ShiftRows step
    fn shift_rows(state: &mut [u8; 16]) {
        let mut temp = [0u8; 16];
        temp.copy_from_slice(state);
        
        // Row 0: No shift
        state[0] = temp[0];
        state[4] = temp[4];
        state[8] = temp[8];
        state[12] = temp[12];
        
        // Row 1: Shift left by 1
        state[1] = temp[5];
        state[5] = temp[9];
        state[9] = temp[13];
        state[13] = temp[1];
        
        // Row 2: Shift left by 2
        state[2] = temp[10];
        state[6] = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];
        
        // Row 3: Shift left by 3
        state[3] = temp[15];
        state[7] = temp[3];
        state[11] = temp[7];
        state[15] = temp[11];
    }
    
    /// Helper for MixColumns: Multiplies by 2 in GF(2^8)
    fn mul2(byte: u8) -> u8 {
        // Multiply by 2 in GF(2^8) with modular polynomial 0x11B
        if byte & 0x80 != 0 {
            (byte << 1) ^ 0x1B
        } else {
            byte << 1
        }
    }
    
    /// Performs the AES MixColumns step
    fn mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let col_idx = i * 4;
            let s0 = state[col_idx];
            let s1 = state[col_idx + 1];
            let s2 = state[col_idx + 2];
            let s3 = state[col_idx + 3];
            
            // Matrix multiplication in GF(2^8)
            state[col_idx] = Self::mul2(s0) ^ Self::mul2(s1) ^ s1 ^ s2 ^ s3;
            state[col_idx + 1] = s0 ^ Self::mul2(s1) ^ Self::mul2(s2) ^ s2 ^ s3;
            state[col_idx + 2] = s0 ^ s1 ^ Self::mul2(s2) ^ Self::mul2(s3) ^ s3;
            state[col_idx + 3] = Self::mul2(s0) ^ s0 ^ s1 ^ s2 ^ Self::mul2(s3);
        }
    }
    
    /// Adds a round key to the state
    fn add_round_key(state: &mut [u8; 16], round_key: &[u32]) {
        // Ensure we're only using 4 elements
        for i in 0..4 {
            if i < round_key.len() {
                let key_bytes = u32_to_bytes(round_key[i]);
                for j in 0..4 {
                    state[i * 4 + j] ^= key_bytes[j];
                }
            }
        }
    }
    
    /// Inverse of sub_bytes
    fn inv_sub_bytes(state: &mut [u8; 16]) {
        for i in 0..16 {
            state[i] = INV_SBOX[state[i] as usize];
        }
    }
    
    /// Inverse of shift_rows
    fn inv_shift_rows(state: &mut [u8; 16]) {
        let mut temp = [0u8; 16];
        temp.copy_from_slice(state);
        
        // Row 0: No shift
        state[0] = temp[0];
        state[4] = temp[4];
        state[8] = temp[8];
        state[12] = temp[12];
        
        // Row 1: Shift right by 1
        state[1] = temp[13];
        state[5] = temp[1];
        state[9] = temp[5];
        state[13] = temp[9];
        
        // Row 2: Shift right by 2
        state[2] = temp[10];
        state[6] = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];
        
        // Row 3: Shift right by 3
        state[3] = temp[7];
        state[7] = temp[11];
        state[11] = temp[15];
        state[15] = temp[3];
    }
    
    /// Helper for InvMixColumns: Multiply by 0x0e in GF(2^8)
    fn mul14(byte: u8) -> u8 {
        Self::mul2(Self::mul2(Self::mul2(byte))) ^ Self::mul2(Self::mul2(byte)) ^ Self::mul2(byte)
    }
    
    /// Helper for InvMixColumns: Multiply by 0x0d in GF(2^8)
    fn mul13(byte: u8) -> u8 {
        Self::mul2(Self::mul2(Self::mul2(byte))) ^ Self::mul2(Self::mul2(byte)) ^ byte
    }
    
    /// Helper for InvMixColumns: Multiply by 0x0b in GF(2^8)
    fn mul11(byte: u8) -> u8 {
        Self::mul2(Self::mul2(Self::mul2(byte))) ^ Self::mul2(byte) ^ byte
    }
    
    /// Helper for InvMixColumns: Multiply by 0x09 in GF(2^8)
    fn mul9(byte: u8) -> u8 {
        Self::mul2(Self::mul2(Self::mul2(byte))) ^ byte
    }
    
    /// Performs the AES InvMixColumns step
    fn inv_mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let col_idx = i * 4;
            let s0 = state[col_idx];
            let s1 = state[col_idx + 1];
            let s2 = state[col_idx + 2];
            let s3 = state[col_idx + 3];
            
            // Matrix multiplication in GF(2^8)
            state[col_idx] = Self::mul14(s0) ^ Self::mul11(s1) ^ Self::mul13(s2) ^ Self::mul9(s3);
            state[col_idx + 1] = Self::mul9(s0) ^ Self::mul14(s1) ^ Self::mul11(s2) ^ Self::mul13(s3);
            state[col_idx + 2] = Self::mul13(s0) ^ Self::mul9(s1) ^ Self::mul14(s2) ^ Self::mul11(s3);
            state[col_idx + 3] = Self::mul11(s0) ^ Self::mul13(s1) ^ Self::mul9(s2) ^ Self::mul14(s3);
        }
    }
}

impl BlockCipher for Aes128 {
    const BLOCK_SIZE: usize = AES_BLOCK_SIZE;
    
    fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), AES128_KEY_SIZE);
        Aes128 {
            round_keys: Self::expand_key(key),
        }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        assert_eq!(block.len(), AES_BLOCK_SIZE);
        
        // Convert block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);
        
        // Initial round
        Self::add_round_key(&mut state, &self.round_keys[0..4]);
        
        // Main rounds
        for round in 1..10 {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
        }
        
        // Final round (no MixColumns)
        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[40..44]);
        
        // Copy state back to block
        block.copy_from_slice(&state);
    }
    
    fn decrypt_block(&self, block: &mut [u8]) {
        assert_eq!(block.len(), AES_BLOCK_SIZE);
        
        // Convert block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);
        
        // Initial round
        Self::add_round_key(&mut state, &self.round_keys[40..44]);
        
        // Main rounds
        for round in (1..10).rev() {
            Self::inv_shift_rows(&mut state);
            Self::inv_sub_bytes(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
            Self::inv_mix_columns(&mut state);
        }
        
        // Final round
        Self::inv_shift_rows(&mut state);
        Self::inv_sub_bytes(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[0..4]);
        
        // Copy state back to block
        block.copy_from_slice(&state);
    }
    
    fn key_size() -> usize {
        AES128_KEY_SIZE
    }
    
    fn name() -> &'static str {
        "AES-128"
    }
}

// AES-192 implementation

impl Aes192 {
    /// Performs AES-192 key expansion
    fn expand_key(key: &[u8]) -> [u32; 52] {
        assert_eq!(key.len(), AES192_KEY_SIZE);
        
        let mut round_keys = [0u32; 52];
        
        // First round key is the original key
        for i in 0..6 {
            round_keys[i] = bytes_to_u32(&key[i * 4..(i + 1) * 4]);
        }
        
        // Generate additional round keys
        for i in 6..52 {
            let mut temp = round_keys[i - 1];
            
            if i % 6 == 0 {
                temp = sub_word(rotate_word(temp)) ^ RCON[i / 6];
            }
            
            round_keys[i] = round_keys[i - 6] ^ temp;
        }
        
        round_keys
    }
}

impl BlockCipher for Aes192 {
    const BLOCK_SIZE: usize = AES_BLOCK_SIZE;
    
    fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), AES192_KEY_SIZE);
        Aes192 {
            round_keys: Self::expand_key(key),
        }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        assert_eq!(block.len(), AES_BLOCK_SIZE);
        
        // Convert block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);
        
        // Initial round
        Aes128::add_round_key(&mut state, &self.round_keys[0..4]);
        
        // Main rounds (12 rounds for AES-192)
        for round in 1..12 {
            Aes128::sub_bytes(&mut state);
            Aes128::shift_rows(&mut state);
            Aes128::mix_columns(&mut state);
            Aes128::add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
        }
        
        // Final round (no MixColumns)
        Aes128::sub_bytes(&mut state);
        Aes128::shift_rows(&mut state);
        Aes128::add_round_key(&mut state, &self.round_keys[48..52]);
        
        // Copy state back to block
        block.copy_from_slice(&state);
    }
    
    fn decrypt_block(&self, block: &mut [u8]) {
        assert_eq!(block.len(), AES_BLOCK_SIZE);
        
        // Convert block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);
        
        // Initial round
        Aes128::add_round_key(&mut state, &self.round_keys[48..52]);
        
        // Main rounds
        for round in (1..12).rev() {
            Aes128::inv_shift_rows(&mut state);
            Aes128::inv_sub_bytes(&mut state);
            Aes128::add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
            Aes128::inv_mix_columns(&mut state);
        }
        
        // Final round
        Aes128::inv_shift_rows(&mut state);
        Aes128::inv_sub_bytes(&mut state);
        Aes128::add_round_key(&mut state, &self.round_keys[0..4]);
        
        // Copy state back to block
        block.copy_from_slice(&state);
    }
    
    fn key_size() -> usize {
        AES192_KEY_SIZE
    }
    
    fn name() -> &'static str {
        "AES-192"
    }
}

// AES-256 implementation

impl Aes256 {
    /// Performs AES-256 key expansion
    fn expand_key(key: &[u8]) -> [u32; 60] {
        assert_eq!(key.len(), AES256_KEY_SIZE);
        
        let mut round_keys = [0u32; 60];
        
        // First round key is the original key
        for i in 0..8 {
            round_keys[i] = bytes_to_u32(&key[i * 4..(i + 1) * 4]);
        }
        
        // Generate additional round keys
        for i in 8..60 {
            let mut temp = round_keys[i - 1];
            
            if i % 8 == 0 {
                temp = sub_word(rotate_word(temp)) ^ RCON[i / 8];
            } else if i % 8 == 4 {
                // AES-256 adds an extra SubWord step
                temp = sub_word(temp);
            }
            
            round_keys[i] = round_keys[i - 8] ^ temp;
        }
        
        round_keys
    }
}

impl BlockCipher for Aes256 {
    const BLOCK_SIZE: usize = AES_BLOCK_SIZE;
    
    fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), AES256_KEY_SIZE);
        Aes256 {
            round_keys: Self::expand_key(key),
        }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        assert_eq!(block.len(), AES_BLOCK_SIZE);
        
        // Convert block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);
        
        // Initial round
        Aes128::add_round_key(&mut state, &self.round_keys[0..4]);
        
        // Main rounds (14 rounds for AES-256)
        for round in 1..14 {
            Aes128::sub_bytes(&mut state);
            Aes128::shift_rows(&mut state);
            Aes128::mix_columns(&mut state);
            Aes128::add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
        }
        
        // Final round (no MixColumns)
        Aes128::sub_bytes(&mut state);
        Aes128::shift_rows(&mut state);
        Aes128::add_round_key(&mut state, &self.round_keys[56..60]);
        
        // Copy state back to block
        block.copy_from_slice(&state);
    }
    
    fn decrypt_block(&self, block: &mut [u8]) {
        assert_eq!(block.len(), AES_BLOCK_SIZE);
        
        // Convert block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);
        
        // Initial round
        Aes128::add_round_key(&mut state, &self.round_keys[56..60]);
        
        // Main rounds
        for round in (1..14).rev() {
            Aes128::inv_shift_rows(&mut state);
            Aes128::inv_sub_bytes(&mut state);
            Aes128::add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
            Aes128::inv_mix_columns(&mut state);
        }
        
        // Final round
        Aes128::inv_shift_rows(&mut state);
        Aes128::inv_sub_bytes(&mut state);
        Aes128::add_round_key(&mut state, &self.round_keys[0..4]);
        
        // Copy state back to block
        block.copy_from_slice(&state);
    }
    
    fn key_size() -> usize {
        AES256_KEY_SIZE
    }
    
    fn name() -> &'static str {
        "AES-256"
    }
}

#[cfg(test)]
mod tests;