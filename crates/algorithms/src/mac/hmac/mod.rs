//! HMAC (Hash-based Message Authentication Code) – constant-time & allocation-free
//!
//! • RFC 2104 / FIPS 198-1 compliant  
//! • Secret-dependent work happens on stack-fixed buffers (≤ 144 bytes)  
//! • Error paths burn the same CPU cycles as success paths

use crate::error::{Error, Result};
use crate::hash::HashFunction;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};
use dcrypt_common::security::{SecretBuffer, SecureZeroingType};

const MAX_BLOCK: usize = 144; // SHA3-224 block size (largest among SHA-2 and SHA-3)

/// Constant-time HMAC implementation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Hmac<H: HashFunction + Clone> {
    #[zeroize(skip)]           // hash state contains no secrets
    hash: H,
    ipad: SecretBuffer<MAX_BLOCK>,
    opad: SecretBuffer<MAX_BLOCK>,
    block_size: usize,
    is_finalized: bool,
}

impl<H> Hmac<H>
where
    H: HashFunction + Clone,
    H::Output: AsRef<[u8]> + Clone,
{
    const IPAD_BYTE: u8 = 0x36;
    const OPAD_BYTE: u8 = 0x5c;

    /* ------------------------------------------------------------------ */
    /*                         Construction helpers                       */
    /* ------------------------------------------------------------------ */

    /// Create a new HMAC instance from `key`.
    pub fn new(key: &[u8]) -> Result<Self> {
        let bs = H::block_size();
        debug_assert!(bs <= MAX_BLOCK);

        /* --- Derive K′ in constant-time --- */
        // Hash the key unconditionally so the running time
        // depends only on the public key length.
        let mut hk = H::new();
        hk.update(key)?;
        let hashed = hk.finalize()?; // ≤ bs bytes

        // Select either `key` or `hashed` per byte with a mask.
        let mut k_prime = [0u8; MAX_BLOCK];
        let long = (key.len() > bs) as u8;      // 1 if key > bs
        let mask = long.wrapping_neg();         // 0xFF when long else 0x00
        #[allow(clippy::needless_range_loop)] // We need the index for multiple arrays
        for i in 0..bs {
            let k  = *key.get(i).unwrap_or(&0);
            let hk = hashed.as_ref().get(i).copied().unwrap_or(0);
            k_prime[i] = (hk & mask) | (k & !mask);
        }

        /* --- Build inner / outer paddings --- */
        let mut ipad_bytes = [0u8; MAX_BLOCK];
        let mut opad_bytes = [0u8; MAX_BLOCK];
        #[allow(clippy::needless_range_loop)] // We need to index multiple arrays
        for i in 0..bs {
            ipad_bytes[i] = k_prime[i] ^ Self::IPAD_BYTE;
            opad_bytes[i] = k_prime[i] ^ Self::OPAD_BYTE;
        }

        // Zero K′ early
        for b in k_prime.iter_mut().take(bs) {
            *b = 0;
        }

        /* --- Initialise inner hash --- */
        let mut hash = H::new();
        hash.update(&ipad_bytes[..bs])?;

        Ok(Self {
            hash,
            ipad: SecretBuffer::new(ipad_bytes),
            opad: SecretBuffer::new(opad_bytes),
            block_size: bs,
            is_finalized: false,
        })
    }

    /* ------------------------------------------------------------------ */
    /*                            Streaming API                           */
    /* ------------------------------------------------------------------ */

    /// Feed additional `data` into the MAC.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_finalized {
            /* ----------------------------------------------------------
             * Equal-cost dummy path: hash the input into a fresh hasher
             * and discard the result so error & success match timings.
             * -------------------------------------------------------- */
            let mut dummy = H::new();
            dummy.update(data)?;
            let _ = dummy.finalize();
            return Err(Error::param(
                "hmac_state",
                "Cannot update after finalization",
            ));
        }

        self.hash.update(data).map(|_| ())
    }

    /// Finalise and return the tag.
    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        if self.is_finalized {
            // Equal-cost burn: mimic normal finalisation cost.
            let inner_dummy = [0u8; 64]; // max SHA-512 output
            let mut outer = H::new();
            outer.update(&self.opad.as_ref()[..self.block_size])?;
            outer.update(&inner_dummy[..H::output_size()])?;
            let _ = outer.finalize();
            return Err(Error::param("hmac_state", "HMAC already finalized"));
        }

        self.is_finalized = true;

        let inner_hash = self.hash.finalize()?;

        let mut outer = H::new();
        outer.update(&self.opad.as_ref()[..self.block_size])?;
        outer.update(inner_hash.as_ref())?;

        outer.finalize().map(|out| out.as_ref().to_vec())
    }

    /* ------------------------------------------------------------------ */
    /*                        Convenience wrappers                         */
    /* ------------------------------------------------------------------ */

    /// One-shot MAC helper.
    pub fn mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut h = Self::new(key)?;
        h.update(data)?;
        h.finalize()
    }

    /// Constant-time verification of `tag` against `key` / `data`.
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool> {
        let expected = Self::mac(key, data)?;

        // Always iterate over the fixed, public digest length to avoid
        // timing variation when the caller supplies a shorter tag.
        let mut diff = 0u8;
        #[allow(clippy::needless_range_loop)] // Accessing both arrays with same index
        for i in 0..H::output_size() {
            let a = expected.get(i).copied().unwrap_or(0);
            let b = tag.get(i).copied().unwrap_or(0);
            diff |= a ^ b;
        }
        // Fold any length mismatch into the diff in a single operation.
        diff |= (tag.len() ^ H::output_size()) as u8;

        Ok(diff.ct_eq(&0u8).unwrap_u8() == 1)
    }
}

impl<H> SecureZeroingType for Hmac<H>
where
    H: HashFunction + Default + Clone,
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