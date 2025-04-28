//! Poly1305 message authentication code
//! Implements RFC 8439 using pure limb arithmetic

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use crate::error::{Error, Result};

pub const POLY1305_KEY_SIZE: usize = 32;
pub const POLY1305_TAG_SIZE: usize = 16;

/// Poly1305 MAC using pure limb arithmetic
pub struct Poly1305 {
    r: [u64; 3],    // r split into three 64-bit limbs
    s: [u64; 2],    // s split into two 64-bit limbs
    data: Vec<u8>,  // buffered input data
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

        let r0 = u64::from_le_bytes(r_bytes[0..8].try_into().unwrap());
        let r1 = u64::from_le_bytes(r_bytes[8..16].try_into().unwrap());
        let r2 = 0;

        let s0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
        let s1 = u64::from_le_bytes(key[24..32].try_into().unwrap());

        Poly1305 { r: [r0, r1, r2], s: [s0, s1], data: Vec::new() }
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
            // parse block into three limbs with padding bit
            let mut buf = [0u8; 16];
            buf[..block.len()].copy_from_slice(block);

            let mut n0 = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            let mut n1 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
            let mut n2 = if block.len() == 16 { 1 } else { 0 };

            if block.len() < 16 {
                let bit = (block.len() * 8) as u32;
                if bit < 64 {
                    n0 |= 1u64 << bit;
                } else {
                    n1 |= 1u64 << (bit - 64);
                }
            }

            // h += n
            let (h0, c0) = h[0].overflowing_add(n0);
            let (h1_tmp, c1a) = h[1].overflowing_add(n1);
            let (h1, c1b)    = h1_tmp.overflowing_add(c0 as u64);
            let c1 = (c1a || c1b) as u64;
            let (h2_tmp, _)  = h[2].overflowing_add(n2);
            let (h2, _)      = h2_tmp.overflowing_add(c1);

            h = [h0, h1, h2];
            h = mul_reduce(h, self.r);
        }

        // 2) Final conditional reduction modulo p = 2^130 - 5
        // p limbs little-endian: p0 = 2^64-5, p1 = 2^64-1, p2 = 3
        const P0: u64 = 0xffff_ffff_ffff_fffb;
        const P1: u64 = 0xffff_ffff_ffff_ffff;
        const P2: u64 = 3;

        let mut h0 = h[0];
        let mut h1 = h[1];
        let mut h2 = h[2];

        // compute h - p with borrow chain
        let (h0_p, borrow0)     = h0.overflowing_sub(P0);
        let (h1_p_tmp, b1a)      = h1.overflowing_sub(P1);
        let (h1_p, b1b)          = h1_p_tmp.overflowing_sub(borrow0 as u64);
        let borrow1              = b1a || b1b;
        let (h2_p, borrow2)      = h2.overflowing_sub(P2 + (borrow1 as u64));

        // if no underflow (h >= p), replace (h0,h1,h2)
        if !borrow2 {
            h0 = h0_p;
            h1 = h1_p;
            h2 = h2_p;
        }

        // 3) Add s to the low 128 bits
        let (t0, carry0)       = h0.overflowing_add(self.s[0]);
        let (t1_tmp, _)        = h1.overflowing_add(self.s[1]);
        let (t1, _)            = t1_tmp.overflowing_add(carry0 as u64);

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
    let c1 = (t0 >> 64) as u64; t0 &= 0xffff_ffff_ffff_ffff; t1 += c1 as u128;
    let c2 = (t1 >> 64) as u64; t1 &= 0xffff_ffff_ffff_ffff; t2 += c2 as u128;
    let c3 = (t2 >> 64) as u64; t2 &= 0xffff_ffff_ffff_ffff; t3 += c3 as u128;
    let c4 = (t3 >> 64) as u64; t3 &= 0xffff_ffff_ffff_ffff; t4 += c4 as u128;
    let _c5 = (t4 >> 64) as u64; t4 &= 0xffff_ffff_ffff_ffff;

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
    let f1 = (m0 >> 64) as u64; m0 &= 0xffff_ffff_ffff_ffff; m1 = m1.wrapping_add(f1 as u128);
    let f2 = (m1 >> 64) as u64; m1 &= 0xffff_ffff_ffff_ffff; m2 = m2.wrapping_add(f2 as u128);

    m2 &= 0x3fff_ffff_ffff_ffff;
    [m0 as u64, m1 as u64, m2 as u64]
}



#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    fn rfc_key() -> [u8; 32] {
        hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn test_poly1305_rfc8439_vector() {
        let key = rfc_key();
        let mut p = Poly1305::new(&key);
        let msg = b"Cryptographic Forum Research Group";
        p.update(msg).unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("a8061dc1305136c6c22b8baf0c0127a9")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_empty_message() {
        let key = rfc_key();
        let tag = Poly1305::new(&key).finalize();
        let mut expected = [0u8; 16];
        expected.copy_from_slice(&key[16..32]);
        assert_eq!(tag, expected);
    }

    #[test]
    fn test_chunked_vs_single_update() {
        let key = rfc_key();
        let msg: Vec<u8> =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                .to_vec();
        let mut p1 = Poly1305::new(&key);
        p1.update(&msg).unwrap();
        let mut p2 = Poly1305::new(&key);
        for b in &msg {
            p2.update(&[*b]).unwrap();
        }
        assert_eq!(p1.finalize(), p2.finalize());
    }

    #[test]
    fn test_hello_message() {
        let key = rfc_key();
        let mut p = Poly1305::new(&key);
        p.update(b"Hello").unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("f74f694dcdf0d5131ed59f4b4e760495")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_single_block_message() {
        let key = rfc_key();
        let mut p = Poly1305::new(&key);
        p.update(b"0123456789ABCDEF").unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("e70d564ce526627cb2f56c7657604601")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_multi_block_message() {
        let key = rfc_key();
        let msg = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let mut p = Poly1305::new(&key);
        p.update(msg).unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("8253fca07713cc36043e7aed25d35085")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_poly1305_rfc8439_vector2() {
        let mut key = [0u8; 32];
        key[16..32].copy_from_slice(
            &hex::decode("36e5f6b5c5e06070f0efca96227a863e").unwrap(),
        );
        let mut p = Poly1305::new(&key);
        let text =
            b"Any submission to the IETF intended by the Contributor for \
publication as all or part of an IETF Internet-Draft or RFC";
        p.update(text).unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("36e5f6b5c5e06070f0efca96227a863e")
                .unwrap()
                .as_slice()
        );
    }


    #[test]
    fn test_poly1305_rfc8439_vector5() {
        let mut key = [0u8; 32];
        key[0] = 0x02;
        let mut p = Poly1305::new(&key);
        p.update(&[0xFFu8; 16]).unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("03000000000000000000000000000000")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_poly1305_rfc8439_vector6() {
        let mut key = [0u8; 32];
        key[0] = 0x02;
        for b in &mut key[16..32] {
            *b = 0xFF;
        }
        let mut p = Poly1305::new(&key);
        let mut block = [0u8; 16];
        block[0] = 0x02;
        p.update(&block).unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("03000000000000000000000000000000")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_poly1305_rfc8439_vector7() {
        let mut key = [0u8; 32];
        key[0] = 0x01;
        let mut p = Poly1305::new(&key);
        p.update(&[0xFFu8; 16]).unwrap();
        let mut b2 = [0xFFu8; 16];
        b2[0] = 0xF0;
        p.update(&b2).unwrap();
        let mut b3 = [0u8; 16];
        b3[0] = 0x11;
        p.update(&b3).unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("05000000000000000000000000000000")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_poly1305_rfc8439_vector8() {
        let mut key = [0u8; 32];
        key[0] = 0x01;
        let mut p = Poly1305::new(&key);
        p.update(&[0xFFu8; 16]).unwrap();
        let mut b2 = [0xFEu8; 16];
        b2[0] = 0xFB;
        p.update(&b2).unwrap();
        p.update(&[0x01u8; 16]).unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("00000000000000000000000000000000")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_poly1305_rfc8439_vector10() {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(
            &hex::decode("01000000000000000400000000000000").unwrap(),
        );
        let data = hex::decode(
            "e33594d7505e43b90000000000000000\
             3394d7505e4379cd0100000000000000\
             00000000000000000000000000000000\
             01000000000000000000000000000000",
        )
        .unwrap();
        let mut p = Poly1305::new(&key);
        p.update(&data).unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("14000000000000005500000000000000")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_poly1305_rfc8439_vector11() {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(
            &hex::decode("01000000000000000400000000000000").unwrap(),
        );
        let data = hex::decode(
            "e33594d7505e43b90000000000000000\
             3394d7505e4379cd0100000000000000\
             00000000000000000000000000000000",
        )
        .unwrap();
        let mut p = Poly1305::new(&key);
        p.update(&data).unwrap();
        assert_eq!(
            p.finalize(),
            hex::decode("13000000000000000000000000000000")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn random_vs_chunked_update() {
        let mut rng = StdRng::seed_from_u64(0x123456789ABCDEF0);
        for _ in 0..1_000 {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            let msg_len = (rng.next_u32() % 256) as usize;
            let mut msg = vec![0u8; msg_len];
            rng.fill_bytes(&mut msg);
            let mut p1 = Poly1305::new(&key);
            p1.update(&msg).unwrap();
            let mut p2 = Poly1305::new(&key);
            let mut off = 0;
            while off < msg_len {
                let c = ((rng.next_u32() % 16) + 1) as usize;
                let end = usize::min(off + c, msg_len);
                p2.update(&msg[off..end]).unwrap();
                off = end;
            }
            assert_eq!(p1.finalize(), p2.finalize());
        }
    }

    #[test]
    fn random_empty_update() {
        let mut rng = StdRng::seed_from_u64(0x0FEDCBA987654321);
        for _ in 0..100 {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            let mut p = Poly1305::new(&key);
            p.update(&[]).unwrap();
            p.update(&[]).unwrap();
            let mut expected = [0u8; 16];
            expected.copy_from_slice(&key[16..32]);
            assert_eq!(p.finalize(), expected);
        }
    }
}