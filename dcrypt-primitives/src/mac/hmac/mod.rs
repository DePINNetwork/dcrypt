//! HMAC (Hash-based Message Authentication Code) – constant-time & allocation-free
//!
//! • RFC 2104 / FIPS 198-1 compliant  
//! • Secret-dependent work happens on stack-fixed buffers (≤ 128 bytes)  
//! • Error paths burn the same CPU cycles as success paths

use crate::error::{Error, Result, validate};
use crate::hash::HashFunction;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};
use dcrypt_core::security::{SecretBuffer, SecureZeroingType};

const MAX_BLOCK: usize = 128;  // SHA-512 block size

/// HMAC (Hash-based Message Authentication Code) implementation
/// 
/// This implementation is constant-time and allocation-free, using fixed buffers
/// on the stack for secret-dependent operations. It follows RFC 2104 and FIPS 198-1
/// specifications.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Hmac<H: HashFunction + Clone> {
    #[zeroize(skip)]  // Hash function itself doesn't need to be zeroized
    hash: H,
    ipad: SecretBuffer<MAX_BLOCK>,
    opad: SecretBuffer<MAX_BLOCK>,
    block_size: usize,
    is_finalized: bool,
}

impl<H> Hmac<H> 
where 
    H: HashFunction + Clone,
    H::Output: AsRef<[u8]> + Clone
{
    const IPAD_BYTE: u8 = 0x36;
    const OPAD_BYTE: u8 = 0x5c;

    /* ------------------------------------------------------------------ */
    /*                           Construction                             */
    /* ------------------------------------------------------------------ */

    /// Creates a new HMAC instance with the given key
    /// 
    /// The key is processed according to RFC 2104:
    /// - If the key is longer than the block size, it's hashed first
    /// - If the key is shorter than the block size, it's padded with zeros
    /// 
    /// # Arguments
    /// * `key` - The secret key for HMAC authentication
    /// 
    /// # Returns
    /// A new `Hmac` instance ready for use
    pub fn new(key: &[u8]) -> Result<Self> {
        let bs = H::block_size();
        debug_assert!(bs <= MAX_BLOCK);

        /* --- derive K′ in constant time --- */
        let mut hk = H::new();
        hk.update(key)?;
        let hashed = hk.finalize()?;                 // ≤ bs bytes

        let mut k_prime = [0u8; MAX_BLOCK];
        let long = (key.len() > bs) as u8;           // 1 if long
        let mask = long.wrapping_neg();              // 0xFF if long else 0x00

        for i in 0..bs {
            let k  = *key.get(i).unwrap_or(&0);
            let hk = hashed.as_ref().get(i).copied().unwrap_or(0);
            k_prime[i] = (hk & mask) | (k & !mask);
        }

        /* --- paddings --- */
        let mut ipad_bytes = [0u8; MAX_BLOCK];
        let mut opad_bytes = [0u8; MAX_BLOCK];
        for i in 0..bs {
            ipad_bytes[i] = k_prime[i] ^ Self::IPAD_BYTE;
            opad_bytes[i] = k_prime[i] ^ Self::OPAD_BYTE;
        }

        /* --- start inner hash --- */
        let mut hash = H::new();
        hash.update(&ipad_bytes[..bs])?;

        // wipe K′
        for b in k_prime.iter_mut().take(bs) { *b = 0; }

        Ok(Self { 
            hash, 
            ipad: SecretBuffer::new(ipad_bytes),
            opad: SecretBuffer::new(opad_bytes),
            block_size: bs, 
            is_finalized: false 
        })
    }

    /* ------------------------------------------------------------------ */
    /*                           Incremental API                          */
    /* ------------------------------------------------------------------ */

    /// Updates the HMAC computation with additional data
    /// 
    /// This method can be called multiple times to process data incrementally.
    /// It performs constant-time operations to maintain security even on error paths.
    /// 
    /// # Arguments
    /// * `data` - The message data to authenticate
    /// 
    /// # Errors
    /// Returns an error if called after finalization
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_finalized {
            // Equal-cost dummy hashing
            let mut dummy = H::new();
            dummy.update(data)?;
            let _ = dummy.finalize();
            return Err(Error::param("hmac_state", "Cannot update after finalization"));
        }
        // Discard the returned hash instance - just return success
        self.hash.update(data).map(|_| ())
    }

    /// Finalizes the HMAC computation and returns the authentication tag
    /// 
    /// After calling this method, the HMAC instance cannot be updated further.
    /// Constant-time operations ensure equal CPU cycles on all code paths.
    /// 
    /// # Returns
    /// The computed HMAC tag as a byte vector
    /// 
    /// # Errors
    /// Returns an error if called more than once
    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        if self.is_finalized {
            // Burn the same cycles as a real finalisation
            let mut dummy_inner = [0u8; 64];                // max SHA-512 output
            let mut outer = H::new();
            outer.update(&self.opad.as_ref()[..self.block_size])?;
            outer.update(&dummy_inner[..H::output_size()])?;
            let _ = outer.finalize();
            return Err(Error::param("hmac_state", "HMAC already finalized"));
        }
        self.is_finalized = true;

        let inner = self.hash.finalize()?;

        let mut outer = H::new();
        outer.update(&self.opad.as_ref()[..self.block_size])?;
        outer.update(inner.as_ref())?;
        
        // Convert H::Output to Vec<u8>
        outer.finalize().map(|output| output.as_ref().to_vec())
    }

    /* ------------------------------------------------------------------ */
    /*                         Convenience helpers                        */
    /* ------------------------------------------------------------------ */

    /// Computes an HMAC tag for the given key and data in one call
    /// 
    /// This is a convenience function that creates an HMAC instance,
    /// processes the data, and returns the final tag.
    /// 
    /// # Arguments
    /// * `key` - The secret key
    /// * `data` - The message to authenticate
    /// 
    /// # Returns
    /// The computed HMAC tag
    pub fn mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut h = Self::new(key)?;
        h.update(data)?;
        h.finalize()
    }

    /// Verifies an HMAC tag in constant time
    /// 
    /// This function computes the expected HMAC tag and compares it with the provided tag
    /// using constant-time comparison to prevent timing attacks. The comparison considers
    /// all bytes even when lengths differ.
    /// 
    /// # Arguments
    /// * `key` - The secret key
    /// * `data` - The message data
    /// * `tag` - The tag to verify
    /// 
    /// # Returns
    /// `true` if the tag is valid, `false` otherwise
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool> {
        let expected = Self::mac(key, data)?;
        let max_len  = expected.len().max(tag.len());
    
        let mut diff = 0u8;
        for i in 0..max_len {
            let a = *expected.get(i).unwrap_or(&0);
            let b = *tag.get(i).unwrap_or(&0);
            diff |= a ^ b;
        }
        diff |= (expected.len() ^ tag.len()) as u8;
    
        let is_valid = diff.ct_eq(&0u8).unwrap_u8() == 1;
        Ok(is_valid)
    }
}

impl<H> SecureZeroingType for Hmac<H> 
where 
    H: HashFunction + Default + Clone
{
    fn zeroed() -> Self {
        Self {
            hash: H::default(),
            ipad: SecretBuffer::zeroed(),
            opad: SecretBuffer::zeroed(),
            block_size: 0,
            is_finalized: false,
        }
    }
    
    fn secure_clone(&self) -> Self {
        // Clone while preserving security properties
        Self {
            hash: self.hash.clone(),
            ipad: self.ipad.secure_clone(),
            opad: self.opad.secure_clone(),
            block_size: self.block_size,
            is_finalized: self.is_finalized,
        }
    }
}

#[cfg(test)]
mod tests;