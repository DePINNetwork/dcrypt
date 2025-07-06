//! Argon2 password hashing function with proper error handling
//!
//! This module provides an implementation of the Argon2 password hashing function,
//! which is designed to be resilient against various attacks including
//! time-memory trade-offs and side-channel attacks.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::error::{Error, Result, validate};
// KdfAlgorithm trait, and PasswordHash related types
use super::{KeyDerivationFunction, SecurityLevel, PasswordHashFunction, PasswordHash};
use super::{KdfAlgorithm, KdfOperation}; // KdfAlgorithm is the trait, Argon2Algorithm is our marker
use super::params::ParamProvider; // For ParamProvider trait
use crate::hash::HashFunction;   // Applied Edit 3
use base64::Engine;
use crate::types::{Salt, SecretBytes};
use crate::Argon2Compatible;
use std::collections::BTreeMap;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};
use rand::{CryptoRng, RngCore};
use core::convert::TryInto;
use crate::hash::blake2::Blake2b;

// Argon2 specific constants
const ARGON2_VERSION_1_3: u32 = 0x13;
const ARGON2_BLOCK_SIZE: usize = 1024;
const ARGON2_QWORDS_IN_BLOCK: usize = ARGON2_BLOCK_SIZE / 8; // 128 qwords
const ARGON2_SYNC_POINTS: u32 = 4; // Number of synchronization points (slices) per pass per lane

const ARGON2_PREHASH_SEED_LENGTH: usize = 72;

/// Creates a Blake2b instance configured for Argon2's H₀ function (pre-hash)
/// according to RFC 9106 Table 3.
/// 
/// Per RFC 9106 Table 3, H₀ parameters are:
/// - digest_length = 64
/// - key_length = 0
/// - fanout = 1 (tree hashing is disabled)
/// - depth = 1
/// - inner_length = 0
fn create_blake2b_for_h0() -> Blake2b {
    // Build the parameter block according to RFC 9106 Table 3
    let mut param = [0u8; 64];
    param[0] = 64;    // digest_length = 64
    param[1] = 0;     // key_length = 0
    param[2] = 1;     // fanout = 1
    param[3] = 1;     // depth = 1
    // leaf_length (4..7) = 0
    // node_offset (8..15) = 0
    param[16] = 0;    // node_depth = 0
    param[17] = 0;    // inner_length = 0 (critical for H₀)
    
    // Initialize Blake2b with these parameters
    Blake2b::with_parameter_block(param, 64)
}

/// A simple Hʷ(x) = BLAKE2b(digest_length = x, tree disabled) for Argon2's H′ function
/// 
/// Per RFC 9106 § 3.2, H^x() should be plain BLAKE2b with tree-hashing disabled.
/// - digest_length = output_len
/// - key_length = 0
/// - fanout = 1 (tree hashing is disabled)
/// - depth = 1
/// - inner_length = 0 (disables tree hashing)
///
/// # Arguments
/// * `digest_len` - The desired output length in bytes
fn blake2b_params(digest_len: u8) -> Blake2b {
    let mut param = [0u8; 64];
    param[0] = digest_len; // digest_length = x
    param[1] = 0;          // key_length = 0
    param[2] = 1;          // fanout = 1
    param[3] = 1;          // depth = 1
    // leaf_length (4..7) = 0
    // node_offset (8..15) = 0
    param[16] = 0;         // node_depth = 0
    param[17] = 0;         // inner_length = 0 disables tree hashing
    
    Blake2b::with_parameter_block(param, digest_len as usize)
}

// Applied Edit 5: New Block struct and type alias
/// Block structure used by Argon2 algorithm
#[derive(Clone)]
struct Block([u8; ARGON2_BLOCK_SIZE]);

impl Zeroize for Block {
    fn zeroize(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// Memory block type alias
type MemBlock = Block;      // replace the old alias

// ─── BLAMKA round + G mixing ──────────────────────────────────────────

#[inline(always)]
fn mul_alpha(x: u64, y: u64) -> u64 {
    2u64
        .wrapping_mul(x & 0xFFFF_FFFF)
        .wrapping_mul(y & 0xFFFF_FFFF)
}

#[inline(always)]
fn blamka(a: u64, b: u64, c: u64, d: u64) -> (u64, u64, u64, u64) {
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;

    a = a.wrapping_add(b).wrapping_add(mul_alpha(a, b));
    d ^= a; d = d.rotate_right(32);
    c = c.wrapping_add(d).wrapping_add(mul_alpha(c, d));
    b ^= c; b = b.rotate_right(24);
    a = a.wrapping_add(b).wrapping_add(mul_alpha(a, b));
    d ^= a; d = d.rotate_right(16);
    c = c.wrapping_add(d).wrapping_add(mul_alpha(c, d));
    b ^= c; b = b.rotate_right(63);

    (a, b, c, d)
}

#[inline(always)]
fn blamka_round(state: &mut [u64; 16]) {
    // Column step
    for &(i, j, k, l) in &[(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15)] {
        let (na,nb,nc,nd) = blamka(state[i],state[j],state[k],state[l]);
        state[i]=na; state[j]=nb; state[k]=nc; state[l]=nd;
    }
    // Diagonal step
    for &(i,j,k,l) in &[(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)] {
        let (na,nb,nc,nd) = blamka(state[i],state[j],state[k],state[l]);
        state[i]=na; state[j]=nb; state[k]=nc; state[l]=nd;
    }
}

/// The Argon2 G mixing function (exactly one blamka_round per row and column,
/// plus feed-forward) as specified in RFC 9106 § 3.5/fig. 15.
fn argon2_g(
    x: &[u64; ARGON2_QWORDS_IN_BLOCK],
    y: &[u64; ARGON2_QWORDS_IN_BLOCK],
) -> [u64; ARGON2_QWORDS_IN_BLOCK] {
    // 1) R = X ⊕ Y
    let mut r = [0u64; ARGON2_QWORDS_IN_BLOCK];
    for i in 0..ARGON2_QWORDS_IN_BLOCK {
        r[i] = x[i] ^ y[i];
    }

    // 2) Row rounds (8 rows of 16 qwords each)
    for chunk in r.chunks_exact_mut(16) {
        let row: &mut [u64;16] = chunk.try_into().unwrap();
        blamka_round(row);
    }

    // 3) Column rounds - correct 16-word selection
    for reg in 0..8 {                       // eight 128-bit registers per row
        let mut tmp = [0u64; 16];
        for row in 0..8 {
            // RFC 9106 Fig. 15 – R is 8×8 of 16-byte registers,
            // so successive rows are 16 q-words apart and successive
            // columns are *1* q-word apart.
            let base = row * 16 + reg * 2;  // low word of register ( *2 because each register = 2 q-words )
            tmp[2 * row]     = r[base];
            tmp[2 * row + 1] = r[base + 1];
        }

        blamka_round(&mut tmp);             // one BLAKE2 round on 16 q-words

        for row in 0..8 {
            let base = row * 16 + reg * 2; 
            r[base]     = tmp[2 * row];
            r[base + 1] = tmp[2 * row + 1];
        }
    }

    // 4) Feed-forward: R_i = R_i ⊕ X_i ⊕ Y_i
    for i in 0..ARGON2_QWORDS_IN_BLOCK {
        r[i] ^= x[i] ^ y[i];
    }

    r
}

/// Argon2 variant types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum Algorithm {
    /// Argon2d variant - uses data-dependent memory access, which offers
    /// the highest resistance against GPU cracking attacks but is vulnerable to side-channel attacks
    Argon2d = 0,
    /// Argon2i variant - uses data-independent memory access, which offers
    /// better protection against side-channel attacks but less resistance against GPU attacks
    Argon2i = 1,
    /// Argon2id variant - hybrid approach that combines Argon2i and Argon2d
    /// for a good balance between resistance to both side-channel and GPU attacks
    Argon2id = 2,
}

/// Parameters for the Argon2 password hashing function
///
/// Argon2 is configurable with several parameters that affect its memory and time cost.
/// This struct encapsulates all the parameters needed to control the behavior of the algorithm.
#[derive(Clone, Zeroize)] // MODIFIED: Removed Default from derive
pub struct Params<const S: usize> where Salt<S>: Argon2Compatible { // MODIFIED: Removed Salt<S>: Default bound
    /// The Argon2 variant to use (Argon2d, Argon2i, or Argon2id)
    pub argon_type: Algorithm,
    /// The Argon2 version (should be 0x13 for v1.3)
    pub version: u32,
    /// Memory usage in kibibytes (KiB)
    pub memory_cost: u32, // KiB
    /// Number of iterations (time cost parameter)
    pub time_cost: u32,   // Iterations
    /// Degree of parallelism (number of threads)
    pub parallelism: u32, // Lanes
    /// Length of the output hash in bytes
    pub output_len: usize,
    /// Salt value for this hash operation
    pub salt: Salt<S>,
    /// Optional associated data that will be included in the hash calculation
    pub ad: Option<Zeroizing<Vec<u8>>>,
    /// Optional secret value that can be used as an additional input
    pub secret: Option<Zeroizing<Vec<u8>>>,
}

// Instead of relying on derive(Default), we'll implement it explicitly
// to ensure all the fields are initialized properly
impl<const S: usize> Default for Params<S> where Salt<S>: Argon2Compatible { // MODIFIED: Removed Salt<S>: Default bound
    fn default() -> Self {
        Params {
            argon_type: Algorithm::Argon2id,
            version: ARGON2_VERSION_1_3,
            memory_cost: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: Salt::<S>::zeroed(), // MODIFIED: Use Salt::zeroed()
            ad: None,
            secret: None,
        }
    }
}

/// Argon2 password hashing implementation
///
/// This struct provides methods for password hashing using the Argon2 algorithm,
/// which is designed to be resistant against various attacks including GPU cracking
/// and side-channel attacks.
#[derive(Clone)]
pub struct Argon2<const S: usize> where Salt<S>: Argon2Compatible {
    /// Configuration parameters for the Argon2 instance
    params: Params<S>,
}


const MAX_PWD_LEN: u32 = 0xFFFFFFFF;
const MIN_SALT_LEN: usize = 8;
const MAX_SALT_LEN: u32 = 0xFFFFFFFF;
const MAX_AD_LEN: u32 = 0xFFFFFFFF;
const MAX_SECRET_LEN: u32 = 0xFFFFFFFF;

const MIN_LANES: u32 = 1;
const MAX_LANES: u32 = 0xFFFFFF;
const MIN_OUT_LEN: usize = 4;
const MAX_OUT_LEN: u32 = 0xFFFFFFFF;
const MIN_TIME_COST: u32 = 1;
const MIN_ABS_MEMORY_COST_KIB: u32 = 8;


impl<const S: usize> Argon2<S>
where
    Salt<S>: Argon2Compatible
{
    /// Creates a new Argon2 instance with the specified parameters
    pub fn new_with_params(params: Params<S>) -> Self {
        Self { params }
    }

    /// Hashes a password using the configured Argon2 parameters
    ///
    /// # Arguments
    /// * `password` - The password to hash
    ///
    /// # Returns
    /// * A `Result` containing the hashed password as a zeroizing byte vector
    pub fn hash_password(&self, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let p = &self.params;
        let salt_bytes = p.salt.as_ref();
        let ad_bytes = p.ad.as_ref().map(|z_vec| z_vec.as_slice());
        let secret_bytes = p.secret.as_ref().map(|z_vec| z_vec.as_slice());

        internal_argon2_core(
            password,
            salt_bytes,
            ad_bytes,
            secret_bytes,
            p.argon_type,
            p.version,
            p.output_len,
            p.memory_cost,
            p.time_cost,
            p.parallelism,
        )
    }
}

/// Fills an address block for a segment in the data-independent addressing mode
///
/// This function computes the address values needed for data-independent addressing
/// in Argon2i and Argon2id variants.
#[allow(clippy::too_many_arguments)]
fn fill_address_block_for_segment(
    address_qwords: &mut [u64; ARGON2_QWORDS_IN_BLOCK],
    pass: u32,
    lane: u32,
    slice: u32,
    m_prime: u32,
    t_cost: u32,
    alg: Algorithm,
    counter: u64,                 // New parameter for the block counter!
    buf: &mut Block,
) -> Result<()> {
    // 1) zero the 1024-byte buffer
    buf.zeroize();

    // 2) write the first 7 qwords: pass, lane, slice, m′, t, y, counter
    let mut off = 0;
    buf.0[off..off+8].copy_from_slice(&(pass as u64).to_le_bytes());     off += 8;
    buf.0[off..off+8].copy_from_slice(&(lane as u64).to_le_bytes());     off += 8;
    buf.0[off..off+8].copy_from_slice(&(slice as u64).to_le_bytes());    off += 8;
    buf.0[off..off+8].copy_from_slice(&(m_prime as u64).to_le_bytes());  off += 8;
    buf.0[off..off+8].copy_from_slice(&(t_cost as u64).to_le_bytes());   off += 8;
    
    let y = match alg {
        Algorithm::Argon2i  => 1,
        Algorithm::Argon2id => 2,
        _                   => 0,
    };
    buf.0[off..off+8].copy_from_slice(&(y as u64).to_le_bytes());        off += 8;
    
    // Set the counter (monotonically increasing for each block in the segment)
    buf.0[off..off+8].copy_from_slice(&counter.to_le_bytes());
    // No need to bump off further, the rest is zero

    // unpack into u64 array for G function - FIXED: Using iterator
    let mut input_q = [0u64; ARGON2_QWORDS_IN_BLOCK];
    for (i, chunk) in buf.0.chunks_exact(8).enumerate().take(ARGON2_QWORDS_IN_BLOCK) {
        input_q[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }

    // Apply G twice, per RFC 9106 § 3.3
    let zero = [0u64; ARGON2_QWORDS_IN_BLOCK];
    let block0 = argon2_g(&zero, &input_q);
    let block1 = argon2_g(&zero, &block0);

    // Copy result to output array
    address_qwords.copy_from_slice(&block1);
    Ok(())
}

/// Internal implementation of the Argon2 algorithm
///
/// This function handles the core Argon2 logic with parameter validation and
/// memory management for the hashing process.
#[allow(clippy::too_many_arguments)]
fn internal_argon2_core(
    password: &[u8],
    salt: &[u8],
    ad: Option<&[u8]>,
    secret: Option<&[u8]>,
    argon_type: Algorithm,
    version: u32,
    output_len: usize,
    memory_cost_kib: u32,
    time_cost_iterations: u32,
    parallelism_lanes: u32,
) -> Result<Zeroizing<Vec<u8>>> {

    validate::parameter(output_len >= MIN_OUT_LEN, "output_len", "value is below minimum")?;
    validate::parameter(output_len <= MAX_OUT_LEN as usize, "output_len", "value is above maximum")?;
    // FIXED: Removed always-true comparisons
    validate::parameter(password.len() <= MAX_PWD_LEN as usize, "password_len", "value is above maximum")?;
    validate::parameter(salt.len() >= MIN_SALT_LEN, "salt_len", "value is below minimum")?;
    validate::parameter(salt.len() <= MAX_SALT_LEN as usize, "salt_len", "value is above maximum")?;

    if let Some(ad_data) = ad {
        validate::parameter(ad_data.len() <= MAX_AD_LEN as usize, "ad_len", "value is above maximum")?;
    }
    if let Some(secret_data) = secret {
        validate::parameter(secret_data.len() <= MAX_SECRET_LEN as usize, "secret_len", "value is above maximum")?;
    }

    validate::parameter(time_cost_iterations >= MIN_TIME_COST, "time_cost", "value is below minimum")?;
    // FIXED: Removed always-true comparison with MAX_TIME_COST
    validate::parameter(parallelism_lanes >= MIN_LANES, "parallelism_lanes", "value is below minimum")?;
    validate::parameter(parallelism_lanes <= MAX_LANES, "parallelism_lanes", "value is above maximum")?;

    let effective_min_mem_kib = 8 * parallelism_lanes;
    validate::parameter(memory_cost_kib >= MIN_ABS_MEMORY_COST_KIB, "memory_cost_kib (absolute)", "value is below minimum")?;
    validate::parameter(memory_cost_kib >= effective_min_mem_kib, "memory_cost_kib (vs lanes)", "value is below minimum")?;

    if version != ARGON2_VERSION_1_3 {
        return Err(Error::param("version", "unsupported Argon2 version"));
    }

    let mut h0_buffer_cap = ARGON2_PREHASH_SEED_LENGTH;
    h0_buffer_cap = h0_buffer_cap.max(4 * 7 + password.len() + salt.len() + secret.unwrap_or(&[]).len() + ad.unwrap_or(&[]).len());
    let mut h0_buffer = Zeroizing::new(Vec::with_capacity(h0_buffer_cap));

    h0_buffer.extend_from_slice(&parallelism_lanes.to_le_bytes());
    h0_buffer.extend_from_slice(&(output_len as u32).to_le_bytes());
    h0_buffer.extend_from_slice(&memory_cost_kib.to_le_bytes());
    h0_buffer.extend_from_slice(&time_cost_iterations.to_le_bytes());
    h0_buffer.extend_from_slice(&version.to_le_bytes());
    h0_buffer.extend_from_slice(&(argon_type as u32).to_le_bytes());

    h0_buffer.extend_from_slice(&(password.len() as u32).to_le_bytes());
    h0_buffer.extend_from_slice(password);
    h0_buffer.extend_from_slice(&(salt.len() as u32).to_le_bytes());
    h0_buffer.extend_from_slice(salt);

    let secret_data = secret.unwrap_or(&[]);
    h0_buffer.extend_from_slice(&(secret_data.len() as u32).to_le_bytes());
    h0_buffer.extend_from_slice(secret_data);

    let ad_data = ad.unwrap_or(&[]);
    h0_buffer.extend_from_slice(&(ad_data.len() as u32).to_le_bytes());
    h0_buffer.extend_from_slice(ad_data);

    // Calculate H0 using standard Blake2b-512 with inner_length=0 as per RFC 9106 Table 3
    // IMPORTANT: H0 uses inner_length=0, unlike H' which uses inner_length=64
    // RFC 9106 Table 3 specifies:
    // - H0: digest_length=64, inner_length=0, fanout=1 (tree hashing is disabled)
    // - H': digest_length=output_len, inner_length=64, fanout=1
    let mut h0_hasher = create_blake2b_for_h0();
    h0_hasher.update(&h0_buffer)?;
    let h0_digest = h0_hasher.finalize()?;
    let mut h0 = Zeroizing::new(h0_digest.as_ref().to_vec());
    h0_buffer.zeroize();

    // Memory allocation according to RFC 9106
    // m' = floor(m / (p*4)) * (p*4) 
    let num_memory_blocks_total = (memory_cost_kib / (parallelism_lanes * ARGON2_SYNC_POINTS))
                                * (parallelism_lanes * ARGON2_SYNC_POINTS);

    let lane_length = num_memory_blocks_total / parallelism_lanes;

    if lane_length == 0 {
        return Err(Error::param("memory_cost_kib", "Effective lane length is zero after rounding."));
    }
    let segment_length = lane_length / ARGON2_SYNC_POINTS;

    let mut memory_matrix: Vec<MemBlock> =
        vec![Block([0u8; ARGON2_BLOCK_SIZE]); num_memory_blocks_total as usize];

    for lane_idx in 0..parallelism_lanes {
        let mut block_seed = Zeroizing::new(Vec::with_capacity(h0.len() + 8));

        block_seed.extend_from_slice(&h0);
        block_seed.extend_from_slice(&0u32.to_le_bytes());
        block_seed.extend_from_slice(&lane_idx.to_le_bytes());
        let block0_val = h_prime_variable_output(&block_seed, ARGON2_BLOCK_SIZE)?;
        memory_matrix[(lane_idx * lane_length) as usize].0.copy_from_slice(&block0_val);
        block_seed.clear();

        block_seed.extend_from_slice(&h0);
        block_seed.extend_from_slice(&1u32.to_le_bytes());
        block_seed.extend_from_slice(&lane_idx.to_le_bytes());
        let block1_val = h_prime_variable_output(&block_seed, ARGON2_BLOCK_SIZE)?;
        memory_matrix[(lane_idx * lane_length + 1) as usize].0.copy_from_slice(&block1_val);
    }
    h0.zeroize();

    // This array will hold the generated address block for data-independent addressing
    let mut address_block_qwords = [0u64; ARGON2_QWORDS_IN_BLOCK];
    let mut input_block_buffer = Block([0u8; ARGON2_BLOCK_SIZE]);

    for pass_idx in 0..time_cost_iterations {
        for slice_idx in 0..ARGON2_SYNC_POINTS {
            for lane_idx in 0..parallelism_lanes {
                let data_independent_addressing_for_segment = match argon_type {
                    Algorithm::Argon2i => true,
                    Algorithm::Argon2d => false,
                    Algorithm::Argon2id => pass_idx == 0 && slice_idx < (ARGON2_SYNC_POINTS / 2),
                };

                let first_block_in_segment_offset = if pass_idx == 0 && slice_idx == 0 { 2 } else { 0 };
                
                // FIXED: Address block counter moved outside the inner loop and initialized to 0
                let mut address_block_counter = 0u64;
                
                for block_in_segment_idx in first_block_in_segment_offset..segment_length {
                    let current_block_offset_in_lane = slice_idx * segment_length + block_in_segment_idx;
                    let current_block_abs_idx = (lane_idx * lane_length + current_block_offset_in_lane) as usize;

                    let prev_block_offset_in_lane = if current_block_offset_in_lane == 0 {
                        lane_length - 1
                    } else {
                        current_block_offset_in_lane - 1
                    };
                    let prev_block_abs_idx = (lane_idx * lane_length + prev_block_offset_in_lane) as usize;

                    // Get pseudo-random values for reference block selection
                    let pseudo_rand: u64 = if data_independent_addressing_for_segment {
                        // need_new == true  ➜ (re)generate a 1024-byte address-block
                        //   • start of the segment  (block_in_segment_idx == 0)
                        //   • every 128th block thereafter
                        let need_new = block_in_segment_idx == 0
                                    || block_in_segment_idx as usize % ARGON2_QWORDS_IN_BLOCK == 0;
                        
                        if need_new {
                            // FIXED: Increment the counter by 1 each time instead of using division
                            address_block_counter += 1;
                            
                            // Generate a fresh address block
                            fill_address_block_for_segment(
                                &mut address_block_qwords,
                                pass_idx,
                                lane_idx,
                                slice_idx,
                                num_memory_blocks_total,
                                time_cost_iterations,
                                argon_type,
                                address_block_counter,
                                &mut input_block_buffer,
                            )?;
                        }
                        
                        // J_i ← address_block[i mod 128]
                        address_block_qwords[block_in_segment_idx as usize % ARGON2_QWORDS_IN_BLOCK]
                    } else {
                        // For data-dependent addressing, get the first 8 bytes of the previous block
                        let mut buf = [0u8; 8];
                        buf.copy_from_slice(&memory_matrix[prev_block_abs_idx].0[0..8]);
                        u64::from_le_bytes(buf)
                    };

                    // --- get the two 32-bit words out of the 64-bit pseudo-random value ---
                    let j1 = (pseudo_rand & 0xFFFF_FFFF) as u32;   // LOW  32 bits  = "first" bits (little-endian)
                    let j2 = (pseudo_rand >> 32)            as u32;   // HIGH 32 bits  = "second" bits

                    // --- choose the reference lane (RFC 9106 §3.4.1 step 4) ---------------
                    let ref_lane_val = if pass_idx == 0 && slice_idx == 0 {
                        lane_idx                                // special case in the very first slice
                    } else {
                        j2 % parallelism_lanes                  // ***use   J₂   here***
                    };

                    // Determine reference position within the lane
                    let (ref_idx_in_lane, _area_size) = index_alpha(
                        pass_idx,
                        slice_idx,
                        block_in_segment_idx,
                        lane_length,
                        segment_length,
                        parallelism_lanes,
                        lane_idx,
                        ref_lane_val,
                        j1,
                    );
                    let ref_block_abs_idx = (ref_lane_val * lane_length + ref_idx_in_lane) as usize;

                    let prev_block_data = &memory_matrix[prev_block_abs_idx].0;
                    let ref_block_data = &memory_matrix[ref_block_abs_idx].0;
                    
                    // Get the current block's data (needed for pass > 0) - clone it to avoid borrowing issues
                    let cur_block_data = if pass_idx > 0 {
                        let mut data = [0u8; ARGON2_BLOCK_SIZE]; 
                        data.copy_from_slice(&memory_matrix[current_block_abs_idx].0);
                        data
                    } else {
                        [0u8; ARGON2_BLOCK_SIZE] // Dummy array for pass 0, won't be used
                    };

                    // Parse the blocks into 128-u64 arrays with proper XOR for pass > 0
                    let mut xv = [0u64; ARGON2_QWORDS_IN_BLOCK];
                    let mut yv = [0u64; ARGON2_QWORDS_IN_BLOCK];
                    
                    // FIXED: Using iterator instead of index loop
                    for (i, chunk) in prev_block_data.chunks_exact(8).enumerate().take(ARGON2_QWORDS_IN_BLOCK) {
                        xv[i] = u64::from_le_bytes(chunk.try_into().unwrap());
                    }
                    
                    // FIXED: Using iterator instead of index loop
                    for (i, chunk) in ref_block_data.chunks_exact(8).enumerate().take(ARGON2_QWORDS_IN_BLOCK) {
                        yv[i] = u64::from_le_bytes(chunk.try_into().unwrap());
                    }
                    
                    // Mix with the true Argon2 G function
                    let gq = argon2_g(&xv, &yv);
                    
                    // Serialize back into bytes - FIXED: Using iterator
                    let mut gbytes = [0u8; ARGON2_BLOCK_SIZE];
                    for (i, &qword) in gq.iter().enumerate().take(ARGON2_QWORDS_IN_BLOCK) {
                        let start = i * 8;
                        gbytes[start..start+8].copy_from_slice(&qword.to_le_bytes());
                    }

                    // Final update matches RFC spec exactly
                    if pass_idx == 0 {
                        memory_matrix[current_block_abs_idx].0.copy_from_slice(&gbytes);
                    } else {
                        for k in 0..ARGON2_BLOCK_SIZE {
                            memory_matrix[current_block_abs_idx].0[k] = gbytes[k] ^ cur_block_data[k];
                        }
                    }
                }
            }
        }
    }

    let mut final_block_xor_sum_vec = Zeroizing::new(memory_matrix[(lane_length - 1) as usize].0.to_vec());

    for lane_idx in 1..parallelism_lanes {
        let last_block_in_lane_idx = (lane_idx * lane_length + (lane_length - 1)) as usize;
        for k in 0..ARGON2_BLOCK_SIZE {
            final_block_xor_sum_vec[k] ^= memory_matrix[last_block_in_lane_idx].0[k];
        }
    }

    let final_hash_vec = h_prime_variable_output(&final_block_xor_sum_vec, output_len)?;
    Ok(Zeroizing::new(final_hash_vec))
}

// RFC 9106 §3.3 "Variable-length hash function H′":
fn h_prime_variable_output(data: &[u8], t: usize) -> Result<Vec<u8>> {
    // T = 0 ⇒ empty
    if t == 0 {
        return Ok(vec![]);
    }

    // For T ≤ 64, just one BLAKE2b(T) call
    if t <= 64 {
        let mut h = blake2b_params(t as u8);
        h.update(&u32::to_le_bytes(t as u32))?;
        h.update(data)?;
        let v = h.finalize()?.as_ref().to_vec();
        return Ok(v);
    }

    // T > 64: compute r = ⌈T/32⌉ - 2, produce r of 32 B each + one of (T - 32r)
    // FIXED: Using div_ceil
    let ceil_div = |x: usize, y: usize| x.div_ceil(y);
    let r = ceil_div(t, 32) - 2;

    let mut out = Vec::with_capacity(t);
    // --- V₁:
    let mut h = blake2b_params(64);
    h.update(&u32::to_le_bytes(t as u32))?;
    h.update(data)?;
    let mut prev = h.finalize()?.as_ref().to_vec();
    out.extend_from_slice(&prev[..32]);

    // --- V₂..Vᵣ:
    for _ in 1..r {
        let mut h = blake2b_params(64);
        h.update(&prev)?;
        let v = h.finalize()?.as_ref().to_vec();
        out.extend_from_slice(&v[..32]);
        prev = v;
    }

    // --- Vᵣ₊₁ (final):
    let final_len = t - 32 * r;
    let mut h = blake2b_params(final_len as u8);
    h.update(&prev)?;
    let v = h.finalize()?.as_ref().to_vec();
    out.extend_from_slice(&v);

    Ok(out)
}


/// Calculates the position of a reference block in the memory matrix
///
/// Exact transcription of the algorithm used in the reference C
/// implementation (src/core.c:index_alpha) that matches all RFC 9106
/// test-vectors.
#[allow(clippy::too_many_arguments)]
fn index_alpha(
    pass_idx: u32,
    slice_idx: u32,
    block_in_segment_idx: u32,
    lane_length: u32,
    segment_length: u32,
    _parallelism_lanes: u32,
    current_lane_idx: u32,
    ref_lane_val: u32,
    j1: u32,
) -> (u32, u32) {
    // ── size of the candidate window |W| ───────────────────────────────
    let mut reference_area_size: u32;

    if pass_idx == 0 {
        if slice_idx == 0 {
            // first slice of first pass
            reference_area_size = block_in_segment_idx.saturating_sub(1);
        } else if ref_lane_val == current_lane_idx {
            // same lane
            reference_area_size = slice_idx * segment_length + block_in_segment_idx;
            reference_area_size = reference_area_size.saturating_sub(1); // exclude current block
        } else {
            // different lane
            reference_area_size = slice_idx * segment_length;
            if block_in_segment_idx == 0 {
                reference_area_size = reference_area_size.saturating_sub(1);
            }
        }
    } else {
        // pass > 0
        if ref_lane_val == current_lane_idx {
            reference_area_size = lane_length - segment_length + block_in_segment_idx;
            reference_area_size = reference_area_size.saturating_sub(1);
        } else {
            reference_area_size = lane_length - segment_length;
            if block_in_segment_idx == 0 {
                reference_area_size = reference_area_size.saturating_sub(1);
            }
        }
    }

    // ── map J₁ to a relative position inside |W| ───────────────────────
    let mut phi = j1 as u64;
    phi = (phi * phi) >> 32; // J₁² / 2³²
    let relative_position = if reference_area_size == 0 {
        0
    } else {
        let rhs = ((reference_area_size as u64) * phi) >> 32;
        (reference_area_size as u64).saturating_sub(1).saturating_sub(rhs)
    } as u32;

    // ── starting offset (same for all lanes on pass > 0) ───────────────
    let start_position_offset = if pass_idx == 0 || slice_idx == ARGON2_SYNC_POINTS - 1 {
        0
    } else {
        (slice_idx + 1) * segment_length
    };

    let ref_idx_in_lane =
        (start_position_offset + relative_position) % lane_length;

    (ref_idx_in_lane, reference_area_size)
}


/// Argon2 algorithm identifier for use with the KDF trait system
///
/// This enum serves as a type marker for the Argon2 algorithm when used with
/// the generic key derivation function interfaces.
pub enum Argon2Algorithm {}
impl KdfAlgorithm for Argon2Algorithm {
    const MIN_SALT_SIZE: usize = MIN_SALT_LEN;
    const DEFAULT_OUTPUT_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "argon2";

    fn name() -> String { "Argon2".to_string() }
    fn security_level() -> SecurityLevel { SecurityLevel::L128 }
}


impl<const S: usize> KeyDerivationFunction for Argon2<S>
where
    Salt<S>: Argon2Compatible + Clone + Zeroize + Send + Sync + 'static,
    Params<S>: Default + Clone + Zeroize + Send + Sync + 'static,
{
    type Algorithm = Argon2Algorithm;
    type Salt = Salt<S>;

    fn new() -> Self { Self { params: Params::default() } }

    // FIXED: Elided lifetime
    fn builder(&self) -> impl KdfOperation<'_, Self::Algorithm> where Self: Sized {
        Argon2Builder {
            params: self.params.clone(),
            ikm: None,
            salt_override: None,
            info_override: None,
            length_override: None,
        }
    }

    fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Salt {
        let s = Salt::random_with_size(rng, S).expect("Salt generation failed");
        debug_assert_eq!(s.as_ref().len(), S, "Salt length mismatch");
        s
    }

    fn derive_key(&self, input: &[u8], salt_override: Option<&[u8]>, info_override: Option<&[u8]>, length_override: usize) -> Result<Vec<u8>> {
        let p = &self.params;
        let effective_salt = salt_override.unwrap_or_else(|| p.salt.as_ref());
        let effective_length = if length_override > 0 { length_override } else { p.output_len };
        let effective_ad = info_override.or_else(|| p.ad.as_ref().map(|z_vec| z_vec.as_slice()));
        let effective_secret = p.secret.as_ref().map(|z_vec| z_vec.as_slice());

        let derived_bytes_zeroizing = internal_argon2_core(
            input,
            effective_salt,
            effective_ad,
            effective_secret,
            p.argon_type,
            p.version,
            effective_length,
            p.memory_cost,
            p.time_cost,
            p.parallelism,
        )?;
        Ok(derived_bytes_zeroizing.to_vec())
    }
}

/// Builder for Argon2 key derivation operations
///
/// This struct provides a fluent interface for configuring and executing
/// Argon2 key derivation operations with various parameters.
#[derive(Clone)]
pub struct Argon2Builder<'a, const S: usize>
where
    Salt<S>: Argon2Compatible + Clone + Zeroize + Send + Sync + 'static,
    Params<S>: Clone + Zeroize + Send + Sync + 'static,
{
    params: Params<S>,
    ikm: Option<&'a [u8]>,
    salt_override: Option<&'a [u8]>,
    info_override: Option<&'a [u8]>,
    length_override: Option<usize>,
}

impl<const S: usize> Zeroize for Argon2Builder<'_, S>
where
    Salt<S>: Argon2Compatible + Clone + Zeroize + Send + Sync + 'static,
    Params<S>: Clone + Zeroize + Send + Sync + 'static,
{
    fn zeroize(&mut self) {
        self.params.zeroize();
        // References ikm, salt_override, info_override are not zeroized here.
        // length_override is usize, typically not zeroized.
    }
}


impl<'a, const S: usize> KdfOperation<'a, Argon2Algorithm> for Argon2Builder<'a, S>
where
    Salt<S>: Argon2Compatible + Clone + Zeroize + Send + Sync + 'static,
    Params<S>: Default + Clone + Zeroize + Send + Sync + 'static,
{
    fn with_ikm(mut self, ikm: &'a [u8]) -> Self { self.ikm = Some(ikm); self }
    fn with_salt(mut self, salt: &'a [u8]) -> Self { self.salt_override = Some(salt); self }
    fn with_info(mut self, info: &'a [u8]) -> Self { self.info_override = Some(info); self }
    fn with_output_length(mut self, len: usize) -> Self { self.length_override = Some(len); self }

    fn derive(self) -> Result<Vec<u8>> {
        let ikm = self.ikm.ok_or_else(|| Error::param("input_key_material", "missing"))?;
        let argon_instance_for_derivation = Argon2 { params: self.params };
        let final_length = self.length_override.unwrap_or(argon_instance_for_derivation.params.output_len);

        argon_instance_for_derivation.derive_key(
            ikm,
            self.salt_override,
            self.info_override,
            final_length
        )
    }

    fn derive_array<const N: usize>(self) -> Result<[u8; N]> {
        let ikm = self.ikm.ok_or_else(|| Error::param("input_key_material", "missing"))?;
        let argon_instance_for_derivation = Argon2 { params: self.params };

        let vec_result = argon_instance_for_derivation.derive_key(
            ikm,
            self.salt_override,
            self.info_override,
            N
        )?;

        vec_result.try_into().map_err(|v_err: Vec<u8>| {
            Error::Length {
                context: "Argon2 derive_array output conversion",
                expected: N,
                actual: v_err.len(),
            }
        })
    }
}

impl<const S: usize> ParamProvider for Argon2<S>
where
    Salt<S>: Argon2Compatible,
    Params<S>: Default + Clone + Zeroize + Send + Sync + 'static,
{
    type Params = Params<S>;

    fn with_params(params: Self::Params) -> Self {
        Self { params }
    }
    fn params(&self) -> &Self::Params {
        &self.params
    }
    fn set_params(&mut self, params: Self::Params) {
        self.params = params;
    }
}


impl<const S: usize> PasswordHashFunction for Argon2<S>
where
    Salt<S>: Argon2Compatible + Clone + Zeroize + Send + Sync + 'static,
    Params<S>: Default + Clone + Zeroize + Send + Sync + 'static,
{
    type Password = SecretBytes<32>;

    fn hash_password(&self, password: &Self::Password) -> Result<PasswordHash> {
        let hashed_output_zeroizing = self.hash_password(password.as_ref())?;

        let type_str = match self.params.argon_type {
            Algorithm::Argon2d => "argon2d",
            Algorithm::Argon2i => "argon2i",
            Algorithm::Argon2id => "argon2id",
        };

        let mut ph_params_map = BTreeMap::new();
        ph_params_map.insert("v".to_string(), self.params.version.to_string());
        ph_params_map.insert("m".to_string(), self.params.memory_cost.to_string());
        ph_params_map.insert("t".to_string(), self.params.time_cost.to_string());
        ph_params_map.insert("p".to_string(), self.params.parallelism.to_string());
        if let Some(ad_val) = &self.params.ad {
            // PHC spec §3: keyid/data fields are *unpadded* Base64.
            ph_params_map.insert(
                "data".to_string(),
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(ad_val)
            );
        }

        Ok(PasswordHash {
            algorithm: type_str.to_string(),
            params: ph_params_map,
            salt: Zeroizing::new(self.params.salt.as_ref().to_vec()),
            hash: hashed_output_zeroizing,
        })
    }

    fn verify(&self, password: &Self::Password, stored_hash: &PasswordHash) -> Result<bool> {
        let argon_variant_from_hash = match stored_hash.algorithm.as_str() {
            "argon2d" => Algorithm::Argon2d,
            "argon2i" => Algorithm::Argon2i,
            "argon2id" => Algorithm::Argon2id,
            _ => return Err(Error::param("algorithm", "Unsupported algorithm in stored hash")),
        };

        let version = stored_hash.param_as_u32("v")?;
        if version != ARGON2_VERSION_1_3 {
             return Err(Error::param("version", "Version mismatch in stored hash"));
        }

        let memory_cost = stored_hash.param_as_u32("m")?;
        let time_cost = stored_hash.param_as_u32("t")?;
        let parallelism = stored_hash.param_as_u32("p")?;

        let ad_from_params: Option<Zeroizing<Vec<u8>>> = stored_hash
            .params
            .get("data")
            .map(|s| base64::engine::general_purpose::STANDARD_NO_PAD
                      .decode(s)
                      .map(Zeroizing::new))
            .transpose()
            .map_err(|_| Error::param("data", "Invalid AD encoding in stored hash (expected Base64)"))?;

        let secret_for_verification = self.params.secret.as_ref().map(|z_vec| z_vec.as_slice());

        let computed_hash_zeroizing = internal_argon2_core(
            password.as_ref(),
            &stored_hash.salt,
            ad_from_params.as_ref().map(|z| z.as_slice()),
            secret_for_verification,
            argon_variant_from_hash,
            version,
            stored_hash.hash.len(),
            memory_cost,
            time_cost,
            parallelism,
        )?;

        Ok(crate::kdf::common::constant_time_eq(&computed_hash_zeroizing, &stored_hash.hash))
    }

    fn benchmark(&self) -> Duration {
        Duration::from_millis(150) // Placeholder
    }

    fn recommended_params(_target_duration: Duration) -> Self::Params {
        Params::default() // Placeholder
    }
}

#[cfg(test)]
mod tests;