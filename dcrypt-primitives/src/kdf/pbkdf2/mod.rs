//! Password-Based Key Derivation Function 2 (PBKDF2)
//!
//! This module implements PBKDF2 as specified in RFC 8018.
//! PBKDF2 applies a pseudorandom function (such as HMAC) to the input password
//! along with a salt value and repeats the process many times to produce a
//! derived key, which can then be used as a cryptographic key in subsequent operations.

#![cfg_attr(not(feature = "std"), no_std)]

use crate::error::{Error, Result};
use crate::hash::HashFunction;
use crate::mac::hmac::Hmac;
use crate::kdf::{KeyDerivationFunction, ParamProvider, PasswordHashFunction};
use crate::kdf::{SecurityLevel, PasswordHash, KdfAlgorithm, KdfOperation};
use crate::kdf::common::{constant_time_eq, generate_salt};
use crate::types::{Salt, SecretBytes};

// Conditional imports based on features
#[cfg(feature = "std")]
use std::time::{Duration, Instant};
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::collections::BTreeMap;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use core::time::Duration;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use std::marker::PhantomData;
use rand::{CryptoRng, RngCore};

/// Type-level constants for PBKDF2 algorithm
pub enum Pbkdf2Algorithm<H: HashFunction> {
    /// Phantom field for the hash function
    _Hash(PhantomData<H>),
}

impl<H: HashFunction> KdfAlgorithm for Pbkdf2Algorithm<H> {
    const MIN_SALT_SIZE: usize = 16;
    const DEFAULT_OUTPUT_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "PBKDF2";
    
    fn name() -> String {
        format!("{}-{}", Self::ALGORITHM_ID, H::name())
    }
    
    fn security_level() -> SecurityLevel {
        // PBKDF2 security depends on the underlying hash
        match H::output_size() * 8 {
            bits if bits >= 512 => SecurityLevel::L128, // Conservative estimate
            bits if bits >= 384 => SecurityLevel::L128,
            bits if bits >= 256 => SecurityLevel::L128,
            bits => SecurityLevel::Custom(bits as u32 / 2),
        }
    }
}

/// Parameters for PBKDF2
#[derive(Clone, Debug, Zeroize)]
pub struct Pbkdf2Params {
    /// Salt value
    pub salt: Zeroizing<Vec<u8>>,
    
    /// Number of iterations
    pub iterations: u32,
    
    /// Length of derived key in bytes
    pub key_length: usize,
}

impl Default for Pbkdf2Params {
    fn default() -> Self {
        Self {
            salt: generate_salt(16),  // Generate a random 16-byte salt
            iterations: 600_000,      // OWASP recommended minimum as of 2023
            key_length: 32,           // 256 bits
        }
    }
}

/// PBKDF2 implementation using any HMAC-based PRF
/// 
/// PBKDF2 can be used with any pseudorandom function, but this implementation
/// uses HMAC with a configurable hash function.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Pbkdf2<H: HashFunction + Clone> {
    /// The hash function type
    _hash_type: PhantomData<H>,
    
    /// PBKDF2 parameters
    params: Pbkdf2Params,
}

/// PBKDF2 builder implementation
pub struct Pbkdf2Builder<'a, H: HashFunction + Clone> {
    kdf: &'a Pbkdf2<H>,
    ikm: Option<&'a [u8]>,
    salt: Option<&'a [u8]>,
    iterations: u32,
    length: usize,
}

impl<'a, H: HashFunction + Clone> Pbkdf2Builder<'a, H> {
    /// Set the number of iterations
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }
}

impl<'a, H: HashFunction + Clone> KdfOperation<'a, Pbkdf2Algorithm<H>> for Pbkdf2Builder<'a, H> {
    fn with_ikm(mut self, ikm: &'a [u8]) -> Self {
        self.ikm = Some(ikm);
        self
    }
    
    fn with_salt(mut self, salt: &'a [u8]) -> Self {
        self.salt = Some(salt);
        self
    }
    
    fn with_info(self, _info: &'a [u8]) -> Self {
        // PBKDF2 doesn't use info, but we implement for API compatibility
        self
    }
    
    fn with_output_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }
    
    fn derive(self) -> Result<Vec<u8>> {
        let ikm = self.ikm.ok_or_else(|| Error::InvalidParameter("Input keying material is required"))?;
        let salt = self.salt.ok_or_else(|| Error::InvalidParameter("Salt is required"))?;
        
        // Use PBKDF2
        Pbkdf2::<H>::pbkdf2(ikm, salt, self.iterations, self.length)
            .map(|result| result.to_vec())
    }
    
    fn derive_array<const N: usize>(self) -> Result<[u8; N]> {
        // Ensure the requested size matches
        if self.length != N {
            return Err(Error::InvalidLength {
                context: "PBKDF2 output",
                needed: N,
                got: self.length,
            });
        }
        
        let vec = self.derive()?;
        
        // Convert to fixed-size array
        let mut array = [0u8; N];
        array.copy_from_slice(&vec);
        Ok(array)
    }
}

impl<H: HashFunction + Clone> Pbkdf2<H> {
    /// Internal PBKDF2 implementation
    /// 
    /// This implements the core PBKDF2 algorithm as defined in RFC 8018 Section 5.2
    /// 
    /// # Arguments
    /// * `password` - The password to derive the key from
    /// * `salt` - The salt value
    /// * `iterations` - The number of iterations
    /// * `key_length` - The length of the derived key in bytes
    /// 
    /// # Returns
    /// The derived key of length key_length bytes
    pub fn pbkdf2(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // Strict parameter validation
        if iterations == 0 {
            return Err(Error::InvalidParameter("PBKDF2 iteration count must be > 0"));
        }
        if key_length == 0 {
            return Err(Error::InvalidParameter("PBKDF2 output length must be > 0"));
        }        
        let hash_len = H::output_size();

        // Calculate how many blocks we need to generate
        let block_count = (key_length + hash_len - 1) / hash_len;
        
        // Check that the output length is not too large
        // RFC 8018 section 5.2 states that the maximum output length is (2^32 - 1) * hash_len
        if block_count > 0xFFFFFFFF {
            return Err(Error::InvalidLength {
                context: "PBKDF2 output length",
                needed: key_length,
                got: 0xFFFFFFFF * hash_len,
            });
        }
        
        let mut result = Zeroizing::new(Vec::with_capacity(key_length));
        
        // Derive each block of the output
        // Each block is calculated independently using the F function
        for block_index in 1..=block_count {
            let block = Self::pbkdf2_f::<H>(password, salt, iterations, block_index as u32)?;
            
            // Determine how much of this block to use
            // Most blocks are used completely, but the last one might be partial
            let to_copy = if block_index == block_count {
                let remainder = key_length % hash_len;
                if remainder == 0 { hash_len } else { remainder }
            } else {
                hash_len
            };
            
            // Append the needed bytes to the result
            result.extend_from_slice(&block[..to_copy]);
        }
        
        Ok(result)
    }
    
    /// F function for PBKDF2 as defined in RFC 8018
    /// 
    /// This function applies the pseudorandom function (PRF) iteratively and
    /// combines the results by XOR.
    ///
    /// Computes F(P, S, c, i) = U_1 XOR U_2 XOR ... XOR U_c
    /// where U_1 = PRF(P, S || INT_32_BE(i))
    ///       U_j = PRF(P, U_{j-1})
    fn pbkdf2_f<T: HashFunction>(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        block_index: u32,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // First iteration: HMAC(password, salt || block_index)
        // U_1 = PRF(P, S || INT_32_BE(i))
        let mut hmac = Hmac::<T>::new(password)?;
        hmac.update(salt)?;
        hmac.update(&block_index.to_be_bytes())?;
        let result = Zeroizing::new(hmac.finalize()?);
        
        let mut prev = result.clone();
        
        // Subsequent iterations: HMAC(password, prev_result)
        // U_j = PRF(P, U_{j-1})
        // Combine results by XOR: U_1 XOR U_2 XOR ... XOR U_c
        let mut output = Zeroizing::new(result.to_vec());
        
        for _ in 1..iterations {
            let mut hmac = Hmac::<T>::new(password)?;
            hmac.update(&prev)?;
            prev = Zeroizing::new(hmac.finalize()?);
            
            // XOR the result with prev
            for i in 0..output.len() {
                output[i] ^= prev[i];
            }
        }
        
        Ok(output)
    }
}

impl<H: HashFunction + Clone> ParamProvider for Pbkdf2<H> {
    type Params = Pbkdf2Params;
    
    fn with_params(params: Self::Params) -> Self {
        Self {
            _hash_type: PhantomData,
            params,
        }
    }
    
    fn params(&self) -> &Self::Params {
        &self.params
    }
    
    fn set_params(&mut self, params: Self::Params) {
        self.params = params;
    }
}

impl<H: HashFunction + Clone> KeyDerivationFunction for Pbkdf2<H> {
    type Algorithm = Pbkdf2Algorithm<H>;
    type Salt = Salt;
    
    fn new() -> Self {
        Self {
            _hash_type: PhantomData,
            params: Pbkdf2Params::default(),
        }
    }
    
    #[cfg(feature = "alloc")]
    fn derive_key(&self, input: &[u8], salt: Option<&[u8]>, _info: Option<&[u8]>, length: usize) -> Result<Vec<u8>> {
        // Use provided salt or fallback to default from params
        let effective_salt = match salt {
            Some(s) => s,
            None => &self.params.salt,
        };
        
        // Use provided length or fallback to default from params
        let effective_length = if length > 0 { length } else { self.params.key_length };
        
        let result = Self::pbkdf2(input, effective_salt, self.params.iterations, effective_length)?;
        Ok(result.to_vec())
    }
    
    fn builder<'a>(&'a self) -> impl KdfOperation<'a, Self::Algorithm> {
        Pbkdf2Builder {
            kdf: self,
            ikm: None,
            salt: None,
            iterations: self.params.iterations,
            length: self.params.key_length,
        }
    }
    
    fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Salt {
        Salt::random_with_size(rng, Self::Algorithm::MIN_SALT_SIZE)
            .expect("Salt generation failed")
    }
    
    fn security_level() -> SecurityLevel {
        Self::Algorithm::security_level()
    }
}

#[cfg(feature = "std")]
impl<H: HashFunction + Clone> PasswordHashFunction for Pbkdf2<H> {
    type Password = SecretBytes<32>; // Using a 32-byte buffer for passwords
    
    fn hash_password(&self, password: &Self::Password) -> Result<PasswordHash> {
        // Derive the key
        let hash = Self::pbkdf2(password.as_ref(), &self.params.salt, self.params.iterations, self.params.key_length)?;
        
        // Create parameters map
        let mut params = BTreeMap::new();
        params.insert("i".to_string(), self.params.iterations.to_string());
        
        Ok(PasswordHash {
            algorithm: format!("pbkdf2-{}", H::name().to_lowercase()),
            params,
            salt: self.params.salt.clone(),
            hash,
        })
    }
    
    fn verify(&self, password: &Self::Password, hash: &PasswordHash) -> Result<bool> {
        // Verify the algorithm
        let expected_alg = format!("pbkdf2-{}", H::name().to_lowercase());
        if hash.algorithm != expected_alg {
            return Err(Error::InvalidParameter("Algorithm mismatch"));
        }
        
        // Get iterations from the hash parameters
        let iterations = match hash.param("i") {
            Some(i) => i.parse::<u32>().map_err(|_| 
                Error::InvalidParameter("Invalid iterations parameter"))?,
            None => return Err(Error::InvalidParameter("Missing iterations parameter")),
        };
        
        // Derive key with the same parameters
        let derived = Self::pbkdf2(
            password.as_ref(), 
            &hash.salt, 
            iterations, 
            hash.hash.len()
        )?;
        
        // Compare in constant time
        Ok(constant_time_eq(&derived, &hash.hash))
    }
    
    fn benchmark(&self) -> Duration {
        let start = Instant::now();
        let password = SecretBytes::new([0u8; 32]); // Use a dummy password for benchmarking
        
        // If hash_password fails, we still return a valid Duration
        // This is acceptable since benchmark is not critical for security
        match self.hash_password(&password) {
            Ok(_) => {},
            Err(_) => {
                // We could log the error here if we had a logging system
                // For now, we'll just continue and return the elapsed time
                // This gives a reasonable approximation even on error
            }
        }
        
        start.elapsed()
    }
    
    fn recommended_params(target_duration: Duration) -> Self::Params {
        // Start with the default parameters
        let mut params = Pbkdf2Params::default();
        
        // Create a temporary instance
        let instance = Self::with_params(params.clone());
        
        // Measure the current execution time
        let current_duration = instance.benchmark();
        
        // Calculate the ratio and adjust iterations
        let ratio = target_duration.as_secs_f64() / current_duration.as_secs_f64();
        params.iterations = (params.iterations as f64 * ratio) as u32;
        
        // Ensure iterations is at least 10,000
        params.iterations = core::cmp::max(params.iterations, 10_000);
        
        params
    }
}

#[cfg(test)]
mod tests;