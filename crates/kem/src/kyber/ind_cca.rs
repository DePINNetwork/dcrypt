// kem/src/kyber/ind_cca.rs

//! Kyber IND-CCA2 KEM construction using Fujisaki-Okamoto transform.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use algorithms::error::{Result as AlgoResult, Error as AlgoError};
use algorithms::hash::sha3::{Sha3_256, Sha3_512};
use algorithms::hash::HashFunction;
use algorithms::poly::params::Modulus; // Add this import
use algorithms::xof::shake::{ShakeXof128, ShakeXof256};
use algorithms::xof::ExtendableOutputFunction;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroizing, Zeroize};
use subtle::ConstantTimeEq;

use super::params::{KyberParams, KyberPolyModParams, KYBER_SYMKEY_SEED_BYTES, KYBER_RHO_SEED_BYTES, KYBER_NOISE_SEED_BYTES};
use super::cpa_pke::{keypair_cpa, encrypt_cpa, decrypt_cpa};
use super::serialize::{pack_pk, unpack_pk, pack_sk, unpack_sk, pack_ciphertext, unpack_ciphertext};

// Type definitions for IND-CCA2 KEM
pub(crate) type IndCcaPublicKeyBytes = Vec<u8>;
pub(crate) type IndCcaSecretKeyBytes = Vec<u8>;
pub(crate) type IndCcaCiphertextBytes = Vec<u8>;
pub(crate) type SharedSecretBytes = Zeroizing<[u8; KYBER_SYMKEY_SEED_BYTES]>;

// H: SHA3-256
// Output is 32 bytes.
fn H_func(data: &[u8]) -> AlgoResult<[u8; 32]> {
    let mut hasher = Sha3_256::new();
    hasher.update(data)?;
    let digest = hasher.finalize()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

// G: SHA3-512
// Output is 64 bytes, split into two 32-byte values (K, r).
fn G_func(data: &[u8]) -> AlgoResult<([u8; 32], [u8; 32])> {
    let mut hasher = Sha3_512::new();
    hasher.update(data)?;
    let digest = hasher.finalize()?;
    let mut k = [0u8; 32];
    let mut r = [0u8; 32];
    k.copy_from_slice(&digest.as_ref()[0..32]);
    r.copy_from_slice(&digest.as_ref()[32..64]);
    Ok((k, r))
}

// PRF: SHAKE256(key, nonce) -> arbitrary length
// For Kyber, this is often used to generate error/masking polynomials.
// The 'key' here is the noise seed, and 'nonce' is a small integer counter.
fn PRF_func(seed: &[u8; KYBER_NOISE_SEED_BYTES], nonce: u8, out_len: usize) -> AlgoResult<Vec<u8>> {
    let mut xof = ShakeXof256::new();
    xof.update(seed)?;
    xof.update(&[nonce])?; // Domain separation for different polynomials
    xof.squeeze_into_vec(out_len)
}

// XOF: SHAKE128(seed, domain_sep_i, domain_sep_j) -> arbitrary length
// For Kyber, this is used to generate matrix A.
fn XOF_A_func(seed: &[u8; KYBER_RHO_SEED_BYTES], i: u8, j: u8, out_len: usize) -> AlgoResult<Vec<u8>> {
    let mut xof = ShakeXof128::new();
    xof.update(seed)?;
    xof.update(&[i, j])?; // Domain separation for A[i][j]
    xof.squeeze_into_vec(out_len)
}

/// IND-CCA2 Key Generation
pub(crate) fn kem_keygen<P: KyberParams, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> AlgoResult<(IndCcaPublicKeyBytes, IndCcaSecretKeyBytes)> {
    // 1. Generate CPA keypair
    let (pk_cpa, sk_cpa) = keypair_cpa::<P, R>(rng)?;
    
    // 2. Pack public key
    let pk_cca_bytes = pack_pk::<P>(&pk_cpa)?;
    
    // 3. Pack secret key
    let sk_cpa_bytes = pack_sk::<P>(&sk_cpa)?;
    
    // 4. Generate random s_fo (implicit rejection value)
    let mut s_fo = [0u8; KYBER_SYMKEY_SEED_BYTES];
    rng.fill_bytes(&mut s_fo);
    
    // 5. H(pk)
    let h_pk = H_func(&pk_cca_bytes)?;
    
    // 6. Construct CCA secret key: sk_cpa || pk || H(pk) || s_fo
    let mut sk_cca_bytes = Vec::with_capacity(P::SECRET_KEY_BYTES);
    sk_cca_bytes.extend_from_slice(&sk_cpa_bytes);
    sk_cca_bytes.extend_from_slice(&pk_cca_bytes);
    sk_cca_bytes.extend_from_slice(&h_pk);
    sk_cca_bytes.extend_from_slice(&s_fo);
    
    // 7. Zeroize sensitive data
    s_fo.zeroize();
    
    Ok((pk_cca_bytes, sk_cca_bytes))
}

/// IND-CCA2 Encapsulation
pub(crate) fn kem_encaps<P: KyberParams, R: RngCore + CryptoRng>(
    pk_cca_bytes: &IndCcaPublicKeyBytes,
    rng: &mut R,
) -> AlgoResult<(IndCcaCiphertextBytes, SharedSecretBytes)> {
    // 1. Generate random message m
    let mut m_bytes = [0u8; KYBER_SYMKEY_SEED_BYTES];
    rng.fill_bytes(&mut m_bytes);
    
    // 2. H(pk)
    let h_pk = H_func(pk_cca_bytes)?;
    
    // 3. (K_bar, r) = G(m || H(pk))
    let mut g_input = Vec::with_capacity(64);
    g_input.extend_from_slice(&m_bytes);
    g_input.extend_from_slice(&h_pk);
    let (k_bar, r_coins) = G_func(&g_input)?;
    
    // 4. Unpack public key
    let pk_cpa = unpack_pk::<P>(pk_cca_bytes)?;
    
    // 5. Encrypt m using CPA encryption with randomness r
    let ct_cpa = encrypt_cpa::<P, R>(&pk_cpa, &m_bytes, &r_coins, rng)?;
    
    // 6. Pack ciphertext
    let ct_cca_bytes = pack_ciphertext::<P>(&ct_cpa)?;
    
    // 7. K = H(K_bar || H(ct))
    let h_ct = H_func(&ct_cca_bytes)?;
    let mut k_input = Vec::with_capacity(64);
    k_input.extend_from_slice(&k_bar);
    k_input.extend_from_slice(&h_ct);
    let k = H_func(&k_input)?;
    
    // 8. Zeroize sensitive data
    m_bytes.zeroize();
    g_input.zeroize();
    k_input.zeroize();
    
    Ok((ct_cca_bytes, Zeroizing::new(k)))
}

/// IND-CCA2 Decapsulation
pub(crate) fn kem_decaps<P: KyberParams>(
    sk_cca_bytes: &IndCcaSecretKeyBytes,
    ct_cca_bytes: &IndCcaCiphertextBytes,
) -> AlgoResult<SharedSecretBytes> {
    // Parse secret key components
    // CCA secret key format: sk_cpa || pk || H(pk) || s_fo
    let sk_cpa_len = (P::K * KyberPolyModParams::N * 12 + 7) / 8; // Packed polynomial vector
    let pk_len = P::PUBLIC_KEY_BYTES;
    let h_pk_len = 32;
    let s_fo_len = 32;
    
    // Validate total length
    let expected_len = sk_cpa_len + pk_len + h_pk_len + s_fo_len;
    if sk_cca_bytes.len() != expected_len {
        return Err(AlgoError::Processing {
            operation: "kem_decaps",
            details: "invalid secret key length",
        });
    }
    
    let sk_cpa_bytes = &sk_cca_bytes[0..sk_cpa_len];
    let pk_bytes = &sk_cca_bytes[sk_cpa_len..sk_cpa_len + pk_len];
    let h_pk = &sk_cca_bytes[sk_cpa_len + pk_len..sk_cpa_len + pk_len + h_pk_len];
    let s_fo = &sk_cca_bytes[sk_cpa_len + pk_len + h_pk_len..sk_cpa_len + pk_len + h_pk_len + s_fo_len];
    
    // 1. Unpack ciphertext
    let ct_cpa = unpack_ciphertext::<P>(ct_cca_bytes)?;
    
    // 2. Unpack secret key
    let sk_cpa = unpack_sk::<P>(sk_cpa_bytes)?;
    
    // 3. Decrypt to get m'
    let m_prime = decrypt_cpa::<P>(&sk_cpa, &ct_cpa)?;
    
    // 4. (K_bar', r') = G(m' || H(pk))
    let mut g_input = Vec::with_capacity(64);
    g_input.extend_from_slice(m_prime.as_ref());
    g_input.extend_from_slice(h_pk);
    let (k_bar_prime, r_prime) = G_func(&g_input)?;
    
    // 5. Re-encrypt m' to get ct'
    let pk_cpa = unpack_pk::<P>(pk_bytes)?;
    
    // Convert m_prime to fixed-size array for encrypt_cpa
    let mut m_prime_array = [0u8; KYBER_SYMKEY_SEED_BYTES];
    m_prime_array.copy_from_slice(m_prime.as_ref());
    
    let ct_prime_cpa = encrypt_cpa::<P, _>(&pk_cpa, &m_prime_array, &r_prime, &mut rand::thread_rng())?;
    let ct_prime_bytes = pack_ciphertext::<P>(&ct_prime_cpa)?;
    
    // 6. Constant-time comparison: ct' == ct
    let ct_eq = ct_prime_bytes.ct_eq(ct_cca_bytes);
    
    // 7. H(ct)
    let h_ct = H_func(ct_cca_bytes)?;
    
    // 8. Constant-time selection of K_bar' or s_fo
    let mut k_input = Vec::with_capacity(64);
    for i in 0..32 {
        // If ct_eq is true (1), select k_bar_prime[i], otherwise select s_fo[i]
        let mask = ct_eq.unwrap_u8().wrapping_sub(1); // 0x00 if equal, 0xFF if not equal
        let selected = (k_bar_prime[i] & !mask) | (s_fo[i] & mask);
        k_input.push(selected);
    }
    k_input.extend_from_slice(&h_ct);
    
    // 9. K = H(selected || H(ct))
    let k = H_func(&k_input)?;
    
    // 10. Zeroize sensitive data
    g_input.zeroize();
    k_input.zeroize();
    m_prime_array.zeroize();
    
    Ok(Zeroizing::new(k))
}