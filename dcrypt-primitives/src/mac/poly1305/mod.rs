//! Poly1305 message authentication code
//! Implements RFC 8439 using pure limb arithmetic

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use crate::error::{Error, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const POLY1305_KEY_SIZE: usize = 32;
pub const POLY1305_TAG_SIZE: usize = 16;

/// Poly1305 MAC using pure limb arithmetic
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Poly1305 {
    r: [u64; 3],    // Secret key material 
    s: [u64; 2],    // Secret key material
    data: Zeroizing<Vec<u8>>,  // May contain sensitive data
}

impl Poly1305 {
    /// Create a new Poly1305 instance with a 32-byte key
    pub fn new(key: &[u8; POLY1305_KEY_SIZE]) -> Self {
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);
        // clamp r per RFC 8439
        r_bytes[3]  &= 15;
        r_bytes[7]  &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4]  &= 252;
        r_bytes[8]  &= 252;
        r_bytes[12] &= 252;

        // Safe conversion without unwrap() calls
        let r0 = u64::from_le_bytes([
            r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3],
            r_bytes[4], r_bytes[5], r_bytes[6], r_bytes[7]
        ]);
        
        let r1 = u64::from_le_bytes([
            r_bytes[8], r_bytes[9], r_bytes[10], r_bytes[11],
            r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]
        ]);
        
        let r2 = 0;

        // Safe conversion of s values
        let s0 = u64::from_le_bytes([
            key[16], key[17], key[18], key[19],
            key[20], key[21], key[22], key[23]
        ]);
        
        let s1 = u64::from_le_bytes([
            key[24], key[25], key[26], key[27],
            key[28], key[29], key[30], key[31]
        ]);

        Poly1305 { r: [r0, r1, r2], s: [s0, s1], data: Zeroizing::new(Vec::new()) }
    }

    /// Feed data into the Poly1305 computation
    pub fn update(&mut self, chunk: &[u8]) -> Result<()> {
        if !chunk.is_empty() {
            self.data.extend_from_slice(chunk);
        }
        Ok(())
    }

    /// Finalize and return the 16-byte tag
    pub fn finalize(self) -> [u8; POLY1305_TAG_SIZE] {
        // 1) Polynomial processing with mul-reduce
        let mut h = [0u64; 3];
        for block in self.data.chunks(16) {
            // parse block into three limbs, with an appended 1-bit at the correct position
            let mut buf = [0u8; 16];
            buf[..block.len()].copy_from_slice(block);

            // set the "pad" bit:
            //  - if full 16-byte block, we'll add it via n2=1
            //  - otherwise, put the 1 at buf[block.len()]
            let n2 = if block.len() == 16 {
                1
            } else {
                buf[block.len()] = 1;
                0
            };

            // Safe conversion without unwrap() calls
            let n0 = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3],
                buf[4], buf[5], buf[6], buf[7]
            ]);
            
            let n1 = u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11],
                buf[12], buf[13], buf[14], buf[15]
            ]);

            // h += n
            let (h0, c0)    = h[0].overflowing_add(n0);
            let (h1_tmp, c1a) = h[1].overflowing_add(n1);
            let (h1, c1b)   = h1_tmp.overflowing_add(c0 as u64);
            let c1 = (c1a || c1b) as u64;
            let (h2_tmp, _)   = h[2].overflowing_add(n2);
            let (h2, _)       = h2_tmp.overflowing_add(c1);

            h = [h0, h1, h2];
            h = mul_reduce(h, self.r);
        }

        // 2) Final conditional reduction modulo p = 2^130 - 5
        const P0: u64 = 0xffff_ffff_ffff_fffb;
        const P1: u64 = 0xffff_ffff_ffff_ffff;
        const P2: u64 = 3;

        let mut h0 = h[0];
        let mut h1 = h[1];
        let mut h2 = h[2];

        // compute h - p
        let (h0_p, borrow0)     = h0.overflowing_sub(P0);
        let (h1_p_tmp, b1a)      = h1.overflowing_sub(P1);
        let (h1_p, b1b)          = h1_p_tmp.overflowing_sub(borrow0 as u64);
        let borrow1              = b1a || b1b;
        let (h2_p, borrow2)      = h2.overflowing_sub(P2 + (borrow1 as u64));

        // Generate a mask based on borrow2 (0 if true, all 1's if false)
        let mask = (!borrow2 as u64).wrapping_neg();  // This is 0 if borrow2 is true, !0u64 if borrow2 is false

        // Select the correct value using bitwise operations
        h0 = h0 ^ ((h0 ^ h0_p) & mask);
        h1 = h1 ^ ((h1 ^ h1_p) & mask);
        h2 = h2 ^ ((h2 ^ h2_p) & mask);

        // 3) Add s to the low 128 bits (mod 2^128)
        let (t0, carry0)       = h0.overflowing_add(self.s[0]);
        let (t1_tmp, carry1)   = h1.overflowing_add(self.s[1]);
        let (t1, _carry2)      = t1_tmp.overflowing_add(carry0 as u64);

        // Output tag = little-endian t0 || t1
        let mut tag = [0u8; POLY1305_TAG_SIZE];
        tag[..8].copy_from_slice(&t0.to_le_bytes());
        tag[8..].copy_from_slice(&t1.to_le_bytes());
        tag
    }
}

/// Pure limb multiply and reduction: compute (h * r) mod (2^130 - 5)
fn mul_reduce(h: [u64; 3], r: [u64; 3]) -> [u64; 3] {
    let (h0, h1, h2) = (h[0] as u128, h[1] as u128, h[2] as u128);
    let (r0, r1, r2) = (r[0] as u128, r[1] as u128, r[2] as u128);

    // schoolbook multiply
    let mut t0 = h0 * r0;
    let mut t1 = h0 * r1 + h1 * r0;
    let mut t2 = h0 * r2 + h1 * r1 + h2 * r0;
    let mut t3 = h1 * r2 + h2 * r1;
    let mut t4 = h2 * r2;

    // propagate carries
    let c1 = (t0 >> 64) as u64; t0 &= u128::from(u64::MAX); t1 += c1 as u128;
    let c2 = (t1 >> 64) as u64; t1 &= u128::from(u64::MAX); t2 += c2 as u128;
    let c3 = (t2 >> 64) as u64; t2 &= u128::from(u64::MAX); t3 += c3 as u128;
    let c4 = (t3 >> 64) as u64; t3 &= u128::from(u64::MAX); t4 += c4 as u128;
    let _c5 = (t4 >> 64) as u64; t4 &= u128::from(u64::MAX);

    // fold bits ≥2^130 back in via 2^130 ≡ 5 (mod p)
    let high = (t2 >> 2)
             .wrapping_add(t3 << 62)
             .wrapping_add(t4 << 126);
    t2 &= 0x3;

    // combine low limbs with folded carry
    let mut m0 = t0.wrapping_add(high * 5);
    let mut m1 = t1;
    let mut m2 = t2;

    // final carry
    let f1 = (m0 >> 64) as u64; m0 &= u128::from(u64::MAX); m1 = m1.wrapping_add(f1 as u128);
    let f2 = (m1 >> 64) as u64; m1 &= u128::from(u64::MAX); m2 = m2.wrapping_add(f2 as u128);

    m2 &= 0x3fff_ffff_ffff_ffff;
    [m0 as u64, m1 as u64, m2 as u64]
}

#[cfg(test)]
mod tests;