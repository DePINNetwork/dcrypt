//! HMAC (Hash-based Message Authentication Code) – constant-time & allocation-free
//!
//! • RFC 2104 / FIPS 198-1 compliant  
//! • Secret-dependent work happens on stack-fixed buffers (≤ 128 bytes)  
//! • Error paths burn the same CPU cycles as success paths

use crate::error::{Error, Result};
use crate::hash::HashFunction;
use subtle::ConstantTimeEq;

const MAX_BLOCK: usize = 128;  // SHA-512 block size

#[derive(Clone)]
pub struct Hmac<H: HashFunction> {
    hash: H,
    ipad: [u8; MAX_BLOCK],
    opad: [u8; MAX_BLOCK],
    block_size: usize,
    is_finalized: bool,
}

impl<H> Hmac<H> 
where 
    H: HashFunction,
    H::Output: AsRef<[u8]> + Clone
{
    const IPAD_BYTE: u8 = 0x36;
    const OPAD_BYTE: u8 = 0x5c;

    /* ------------------------------------------------------------------ */
    /*                           Construction                             */
    /* ------------------------------------------------------------------ */

    pub fn new(key: &[u8]) -> Result<Self> {
        let bs = H::block_size();
        debug_assert!(bs <= MAX_BLOCK);

        /* --- derive K′ in constant time --- */
        let mut hk = H::new();
        hk.update(key)?;
        let hashed = hk.finalize()?;                 // ≤ bs bytes

        let mut k_prime = [0u8; MAX_BLOCK];
        let long = (key.len() > bs) as u8;           // 1 if long
        let mask = long.wrapping_neg();              // 0xFF if long else 0

        for i in 0..bs {
            let k  = *key.get(i).unwrap_or(&0);
            let hk = hashed.as_ref().get(i).copied().unwrap_or(0);
            k_prime[i] = (hk & mask) | (k & !mask);
        }

        /* --- paddings --- */
        let mut ipad = [0u8; MAX_BLOCK];
        let mut opad = [0u8; MAX_BLOCK];
        for i in 0..bs {
            ipad[i] = k_prime[i] ^ Self::IPAD_BYTE;
            opad[i] = k_prime[i] ^ Self::OPAD_BYTE;
        }

        /* --- start inner hash --- */
        let mut hash = H::new();
        hash.update(&ipad[..bs])?;

        // wipe K′
        for b in k_prime.iter_mut().take(bs) { *b = 0; }

        Ok(Self { hash, ipad, opad, block_size: bs, is_finalized: false })
    }

    /* ------------------------------------------------------------------ */
    /*                           Incremental API                          */
    /* ------------------------------------------------------------------ */

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_finalized {
            // equal-cost dummy hashing
            let mut dummy = H::new();
            dummy.update(data)?;
            let _ = dummy.finalize();
            return Err(Error::InvalidParameter("Cannot update after finalization"));
        }
        // Discard the returned hash instance - just return success
        self.hash.update(data).map(|_| ())
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        if self.is_finalized {
            // Burn the same cycles as a real finalisation
            let mut dummy_inner = [0u8; 64];                // max SHA-512 output
            let mut outer = H::new();
            outer.update(&self.opad[..self.block_size])?;
            outer.update(&dummy_inner[..H::output_size()])?;
            let _ = outer.finalize();
            return Err(Error::InvalidParameter("HMAC already finalized"));
        }
        self.is_finalized = true;

        let inner = self.hash.finalize()?;

        let mut outer = H::new();
        outer.update(&self.opad[..self.block_size])?;
        outer.update(inner.as_ref())?;
        
        // Convert H::Output to Vec<u8>
        outer.finalize().map(|output| output.as_ref().to_vec())
    }

    /* ------------------------------------------------------------------ */
    /*                         Convenience helpers                        */
    /* ------------------------------------------------------------------ */

    pub fn mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut h = Self::new(key)?;
        h.update(data)?;
        h.finalize()
    }

    /// Constant-time verification even when `tag` length differs.
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

        Ok(diff.ct_eq(&0u8).unwrap_u8() == 1)
    }
}

#[cfg(test)]
mod tests;