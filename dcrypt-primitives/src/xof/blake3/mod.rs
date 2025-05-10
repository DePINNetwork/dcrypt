//! Minimal BLAKE3 implementation focusing on correctness over performance
//! Directly adapted from the official reference implementation

use super::{ExtendableOutputFunction, KeyedXof, DeriveKeyXof, Blake3Algorithm};
use crate::error::{Error, Result, validate};
use crate::xof::XofAlgorithm;
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// BLAKE3 constants
const OUT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

// Flags
const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

// IV is the initialization vector for BLAKE3
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// Message word permutation for each round
const MSG_PERMUTATION: [usize; 16] = [
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
];

// Convert bytes to words
fn words_from_little_endian_bytes(bytes: &[u8], words: &mut [u32]) {
    debug_assert_eq!(bytes.len(), 4 * words.len());
    for i in 0..words.len() {
        words[i] = u32::from_le_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
}

// G function for mixing
#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

// Apply a single round of the compression function
fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Column rounds - Mix the four columns
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    
    // Diagonal rounds - Mix the four diagonals
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

// Permute message words for the next round
fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    *m = permuted;
}

// Compression function for BLAKE3
fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let counter_low = counter as u32;
    let counter_high = (counter >> 32) as u32;
    
    // Initialize state with chaining value and IV
    let mut state = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0], IV[1], IV[2], IV[3],
        counter_low, counter_high, block_len, flags,
    ];
    
    let mut block = *block_words;
    
    // BLAKE3 uses exactly 7 rounds
    for r in 0..7 {
        // Apply the round function
        round(&mut state, &block);
        
        // Permute the message words for the next round
        if r < 6 {
            permute(&mut block);
        }
    }
    
    // Create output array for the compression function
    let mut output = [0u32; 16];
    
    // First 8 words: XOR the first half of the state with the second half
    for i in 0..8 {
        output[i] = state[i] ^ state[i + 8];
    }
    
    // Second 8 words: XOR the second half of the state with the input chaining value
    for i in 0..8 {
        output[i + 8] = state[i + 8] ^ chaining_value[i];
    }
    
    output
}

// Get the first 8 words as a chaining value
fn first_8_words(compression_output: &[u32; 16]) -> [u32; 8] {
    let mut result = [0u32; 8];
    result.copy_from_slice(&compression_output[0..8]);
    result
}

// Output structure
#[derive(Clone, Zeroize)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(&compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags
        ))
    }
    
    fn root_output_bytes(&self, out_slice: &mut [u8]) {
        let mut output_block_counter = 0;
        
        for out_block in out_slice.chunks_mut(2 * OUT_LEN) {
            let words = compress(
                &self.input_chaining_value,
                &self.block_words,
                output_block_counter,
                self.block_len,
                self.flags | ROOT
            );
            
            // Copy output bytes - ensure little-endian encoding
            for (i, word) in words.iter().enumerate() {
                let word_bytes = word.to_le_bytes();
                let start = i * 4;
                if start >= out_block.len() {
                    break;
                }
                let end = core::cmp::min((i + 1) * 4, out_block.len());
                out_block[start..end].copy_from_slice(&word_bytes[..(end - start)]);
            }
            
            output_block_counter += 1;
        }
    }
}

// Chunk state
#[derive(Clone, Zeroize)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value: key_words,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }
    
    fn len(&self) -> usize {
        (self.blocks_compressed as usize) * BLOCK_LEN + (self.block_len as usize)
    }
    
    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }
    
    // Internal update implementation
    fn update_internal(&mut self, mut input: &[u8]) -> Result<()> {
        // Check if adding this input would exceed chunk size limit
        if self.len() + input.len() > CHUNK_LEN {
            let want = CHUNK_LEN - self.len();
            self.update_internal(&input[..want])?;
            return Ok(());
        }

        while !input.is_empty() {
            // If the block is full, compress it
            if self.block_len as usize == BLOCK_LEN {
                let mut block_words = [0u32; 16];
                words_from_little_endian_bytes(&self.block, &mut block_words);
                
                self.chaining_value = first_8_words(&compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag()
                ));
                
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            
            // Copy input data into the block
            let want = BLOCK_LEN - self.block_len as usize;
            let take = core::cmp::min(want, input.len());
            
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            
            self.block_len += take as u8;
            input = &input[take..];
        }
        
        Ok(())
    }
    
    // Public update method to maintain compatibility with tests
    pub fn update(&mut self, input: &[u8]) -> Result<()> {
        self.update_internal(input)
    }
    
    fn output(&self) -> Output {
        // Zero-pad the block to create a full set of block words
        let mut block_words = [0u32; 16];
        let mut padded_block = [0u8; BLOCK_LEN];
        padded_block[..self.block_len as usize].copy_from_slice(&self.block[..self.block_len as usize]);
        words_from_little_endian_bytes(&padded_block, &mut block_words);
        
        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

// Parent node creation
fn parent_output(
    left_child_cv: [u32; 8],
    right_child_cv: [u32; 8],
    key_words: [u32; 8],
    flags: u32
) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left_child_cv);
    block_words[8..].copy_from_slice(&right_child_cv);
    
    Output {
        input_chaining_value: key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

// Parent chaining value
fn parent_cv(
    left_child_cv: [u32; 8],
    right_child_cv: [u32; 8],
    key_words: [u32; 8],
    flags: u32
) -> [u32; 8] {
    parent_output(left_child_cv, right_child_cv, key_words, flags).chaining_value()
}

/// BLAKE3 extendable output function
#[derive(Clone, Zeroize)]
pub struct Blake3Xof {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    cv_stack: Vec<[u32; 8]>,
    flags: u32,
}

impl Blake3Xof {
    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack.push(cv);
    }
    
    fn pop_stack(&mut self) -> Result<[u32; 8]> {
        self.cv_stack.pop().ok_or_else(|| Error::Processing {
            operation: "BLAKE3",
            details: "Stack underflow",
        })
    }
    
    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) -> Result<()> {
        while total_chunks & 1 == 0 {
            new_cv = parent_cv(self.pop_stack()?, new_cv, self.key_words, self.flags);
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
        Ok(())
    }
    
    fn finalize(&mut self, out_slice: &mut [u8]) -> Result<()> {
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack.len();
        
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output = parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            );
        }
        
        output.root_output_bytes(out_slice);
        Ok(())
    }

    /// Utility function for digest generation
    pub fn generate(data: &[u8], len: usize) -> Result<Vec<u8>> {
        Blake3Algorithm::validate_output_length(len)?;
        
        let mut xof = Self::new();
        xof.update(data)?;
        let mut result = vec![0u8; len];
        xof.squeeze(&mut result)?;
        Ok(result)
    }
}

impl ExtendableOutputFunction for Blake3Xof {
    fn new() -> Self {
        Self {
            chunk_state: ChunkState::new(IV, 0, 0),
            key_words: IV,
            cv_stack: Vec::new(),
            flags: 0,
        }
    }
    
    fn update(&mut self, mut input: &[u8]) -> Result<()> {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks)?;
                self.chunk_state = ChunkState::new(self.key_words, total_chunks, self.flags);
            }
            
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = core::cmp::min(want, input.len());
            self.chunk_state.update_internal(&input[..take])?;
            input = &input[take..];
        }
        
        Ok(())
    }
    
    fn finalize(&mut self) -> Result<()> {
        Ok(())
    }
    
    fn squeeze(&mut self, output: &mut [u8]) -> Result<()> {
        Blake3Algorithm::validate_output_length(output.len())?;
        self.finalize(output)
    }
    
    fn squeeze_into_vec(&mut self, len: usize) -> Result<Vec<u8>> {
        Blake3Algorithm::validate_output_length(len)?;
        let mut result = vec![0u8; len];
        self.squeeze(&mut result)?;
        Ok(result)
    }
    
    fn reset(&mut self) -> Result<()> {
        *self = Self::new();
        Ok(())
    }
    
    fn security_level() -> usize {
        Blake3Algorithm::SECURITY_LEVEL
    }
}

impl KeyedXof for Blake3Xof {
    fn with_key(key: &[u8]) -> Result<Self> {
        validate::length("BLAKE3 key", key.len(), KEY_LEN)?;
        
        // Convert key to key words
        let mut key_words = [0u32; 8];
        words_from_little_endian_bytes(key, &mut key_words);
        
        Ok(Self {
            chunk_state: ChunkState::new(key_words, 0, KEYED_HASH),
            key_words,
            cv_stack: Vec::new(),
            flags: KEYED_HASH,
        })
    }
}

impl DeriveKeyXof for Blake3Xof {
    fn for_derive_key(context: &[u8]) -> Result<Self> {
        let mut context_hasher = Self::new();
        context_hasher.update(context)?;
        
        // Create key from context using DERIVE_KEY_CONTEXT flag
        let context_key = {
            let mut tmp = [0u8; KEY_LEN];
            let mut output = context_hasher.chunk_state.output();
            output.flags |= DERIVE_KEY_CONTEXT;
            output.root_output_bytes(&mut tmp);
            tmp
        };
        
        // Convert context key to key words
        let mut key_words = [0u32; 8];
        words_from_little_endian_bytes(&context_key, &mut key_words);
        
        Ok(Self {
            chunk_state: ChunkState::new(key_words, 0, DERIVE_KEY_MATERIAL),
            key_words,
            cv_stack: Vec::new(),
            flags: DERIVE_KEY_MATERIAL,
        })
    }
}

#[cfg(test)]
mod tests;