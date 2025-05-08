//! HMAC-based Key Derivation Function (HKDF)
//!
//! This module implements HKDF as defined in RFC 5869.
//! HKDF is designed to take input keying material (IKM) that is not necessarily
//! uniform and produce output keying material (OKM) suitable for use in cryptographic
//! contexts.

use crate::error::{Error, Result};
use crate::hash::HashFunction;
use crate::mac::hmac::Hmac;
use crate::kdf::{KeyDerivationFunction, ParamProvider, SecurityLevel, KdfAlgorithm, KdfOperation};
use crate::types::Salt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand::{CryptoRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use std::marker::PhantomData;

/// Type-level constants for HKDF algorithm
pub enum HkdfAlgorithm<H: HashFunction> {
    /// Phantom field for the hash function
    _Hash(PhantomData<H>),
}

impl<H: HashFunction> KdfAlgorithm for HkdfAlgorithm<H> {
    const MIN_SALT_SIZE: usize = 16;
    const DEFAULT_OUTPUT_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "HKDF";
    
    fn name() -> String {
        format!("{}-{}", Self::ALGORITHM_ID, H::name())
    }
    
    fn security_level() -> SecurityLevel {
        match H::output_size() * 8 {
            bits if bits >= 512 => SecurityLevel::L256,
            bits if bits >= 384 => SecurityLevel::L192,
            bits if bits >= 256 => SecurityLevel::L128,
            bits => SecurityLevel::Custom(bits as u32 / 2),
        }
    }
}

/// Parameters for HKDF
#[derive(Clone, Debug, Zeroize)]
pub struct HkdfParams {
    /// Optional default salt (can be overridden in derive_key)
    pub salt: Option<Zeroizing<Vec<u8>>>,
    /// Optional default info (context, can be overridden in derive_key)
    pub info: Option<Zeroizing<Vec<u8>>>,
}

impl Default for HkdfParams {
    fn default() -> Self {
        Self { salt: None, info: None }
    }
}

/// HKDF implementation using any hash function
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Hkdf<H: HashFunction> {
    _hash_type: PhantomData<H>,
    params: HkdfParams,
}

/// Operation for HKDF operations
pub struct HKdfOperation<'a, H: HashFunction> {
    kdf: &'a Hkdf<H>,
    ikm: Option<&'a [u8]>,
    salt: Option<&'a [u8]>,
    info: Option<&'a [u8]>,
    length: usize,
}

impl<'a, H: HashFunction> KdfOperation<'a, HkdfAlgorithm<H>> for HKdfOperation<'a, H> {
    fn with_ikm(mut self, ikm: &'a [u8]) -> Self {
        self.ikm = Some(ikm);
        self
    }
    
    fn with_salt(mut self, salt: &'a [u8]) -> Self {
        self.salt = Some(salt);
        self
    }
    
    fn with_info(mut self, info: &'a [u8]) -> Self {
        self.info = Some(info);
        self
    }
    
    fn with_output_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }
    
    fn derive(self) -> Result<Vec<u8>> {
        let ikm = self.ikm.ok_or_else(|| Error::InvalidParameter("Input keying material is required"))?;
        
        let salt = self.salt.or_else(|| self.kdf.params.salt.as_ref().map(|s| s.as_slice()));
        let info = self.info.or_else(|| self.kdf.params.info.as_ref().map(|i| i.as_slice()));
        
        // Fix: Convert Zeroizing<Vec<u8>> to Vec<u8>
        Hkdf::<H>::derive(salt, ikm, info, self.length)
            .map(|result| result.to_vec())
    }
    
    fn derive_array<const N: usize>(self) -> Result<[u8; N]> {
        // Ensure the requested size matches
        if self.length != N {
            return Err(Error::InvalidLength {
                context: "HKDF output",
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

impl<H: HashFunction> Hkdf<H> {
    /// HKDF-Extract
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let salt_bytes = salt.unwrap_or(&[]);
        let result = Hmac::<H>::mac(salt_bytes, ikm)?;
        Ok(Zeroizing::new(result))
    }

    /// HKDF-Expand
    pub fn expand(prk: &[u8], info: Option<&[u8]>, length: usize) -> Result<Zeroizing<Vec<u8>>> {
        let hash_len = H::output_size();
        let max_len = 255 * hash_len;

        // Specified max-length check (length is public)
        if length > max_len {
            return Err(Error::InvalidLength {
                context: "Output length for HKDF-Expand",
                needed: length,
                got: max_len,
            });
        }

        // PRK length check (must be at least one hash block)
        if prk.len() < hash_len {
            return Err(Error::InvalidLength {
                context: "PRK for HKDF-Expand",
                needed: hash_len,
                got: prk.len(),
            });
        }

        // Number of blocks needed
        let n = (length + hash_len - 1) / hash_len;

        // Pre-allocate OKM buffer and temporary block buffer
        let mut okm = Zeroizing::new(vec![0u8; n * hash_len]);
        let mut t_buf = Zeroizing::new(vec![0u8; hash_len]);
        let info_bytes = info.unwrap_or(&[]);

        for i in 1..=n {
            let mut hmac = Hmac::<H>::new(prk)?;
            if i > 1 {
                // feed previous block for iterations > 1
                hmac.update(&t_buf)?;
            }
            hmac.update(info_bytes)?;
            hmac.update(&[i as u8])?;
            let block = hmac.finalize()?;
            t_buf.copy_from_slice(&block);
            let start = (i - 1) * hash_len;
            okm[start..start + hash_len].copy_from_slice(&t_buf);
        }

        okm.truncate(length);
        Ok(okm)
    }

    /// Full HKDF (Extract + Expand) with warm-up
    pub fn derive(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: Option<&[u8]>,
        length: usize
    ) -> Result<Zeroizing<Vec<u8>>> {
        let _ = Hmac::<H>::new(&[])?; // warm-up
        let prk = Self::extract(salt, ikm)?;
        Self::expand(&prk, info, length)
    }
}

impl<H: HashFunction> ParamProvider for Hkdf<H> {
    type Params = HkdfParams;
    fn with_params(params: Self::Params) -> Self {
        Hkdf { _hash_type: PhantomData, params }
    }
    fn params(&self) -> &Self::Params {
        &self.params
    }
    fn set_params(&mut self, params: Self::Params) {
        self.params = params;
    }
}

impl<H: HashFunction> KeyDerivationFunction for Hkdf<H> {
    type Algorithm = HkdfAlgorithm<H>;
    type Salt = Salt;
    
    fn new() -> Self {
        Hkdf { _hash_type: PhantomData, params: HkdfParams::default() }
    }
    
    fn derive_key(
        &self,
        input: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        length: usize
    ) -> Result<Vec<u8>> {
        let effective_salt = salt.or_else(|| self.params.salt.as_ref().map(|s| s.as_slice()));
        let effective_info = info.or_else(|| self.params.info.as_ref().map(|i| i.as_slice()));
        let result = Self::derive(effective_salt, input, effective_info, length)?;
        Ok(result.to_vec())
    }
    
    fn builder<'a>(&'a self) -> impl KdfOperation<'a, Self::Algorithm> {
        HKdfOperation {
            kdf: self,
            ikm: None,
            salt: None,
            info: None,
            length: Self::Algorithm::DEFAULT_OUTPUT_SIZE,
        }
    }
    
    fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Salt {
        Salt::random_with_size(rng, Self::Algorithm::MIN_SALT_SIZE)
            .expect("Salt generation failed")
    }
    
    // Changed from instance method to static method
    fn security_level() -> SecurityLevel {
        match H::output_size() * 8 {
            bits if bits >= 512 => SecurityLevel::L256,
            bits if bits >= 384 => SecurityLevel::L192,
            bits if bits >= 256 => SecurityLevel::L128,
            bits => SecurityLevel::Custom(bits as u32 / 2),
        }
    }
}

#[cfg(test)]
mod tests;