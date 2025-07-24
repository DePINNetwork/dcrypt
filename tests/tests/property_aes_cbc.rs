//! Property-based tests for AES-CBC implementation

use dcrypt_algorithms::block::aes::{Aes128, Aes192, Aes256};
use dcrypt_algorithms::block::modes::cbc::Cbc;
use dcrypt_algorithms::block::BlockCipher;
use dcrypt_algorithms::types::{Nonce, SecretBytes};
use proptest::prelude::*;

/// Generate data that's a multiple of 16 bytes (AES block size)
fn block_aligned_data() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 16..=256).prop_map(|mut v| {
        // Pad to 16-byte multiple
        while v.len() % 16 != 0 {
            v.push(0);
        }
        v
    })
}

proptest! {
    #[test]
    fn aes128_cbc_roundtrip(
        key in any::<[u8; 16]>(),
        iv in any::<[u8; 16]>(),
        data in block_aligned_data()
    ) {
        let secret_key = SecretBytes::<16>::new(key);
        let nonce = Nonce::<16>::new(iv);

        // Encrypt
        let cipher = Aes128::new(&secret_key);
        let cbc_enc = Cbc::new(cipher, &nonce).unwrap();
        let ciphertext = cbc_enc.encrypt(&data).unwrap();

        // Decrypt
        let cipher = Aes128::new(&secret_key);
        let cbc_dec = Cbc::new(cipher, &nonce).unwrap();
        let plaintext = cbc_dec.decrypt(&ciphertext).unwrap();

        prop_assert_eq!(plaintext, data);
    }

    #[test]
    fn aes192_cbc_roundtrip(
        key in any::<[u8; 24]>(),
        iv in any::<[u8; 16]>(),
        data in block_aligned_data()
    ) {
        let secret_key = SecretBytes::<24>::new(key);
        let nonce = Nonce::<16>::new(iv);

        // Encrypt
        let cipher = Aes192::new(&secret_key);
        let cbc_enc = Cbc::new(cipher, &nonce).unwrap();
        let ciphertext = cbc_enc.encrypt(&data).unwrap();

        // Decrypt
        let cipher = Aes192::new(&secret_key);
        let cbc_dec = Cbc::new(cipher, &nonce).unwrap();
        let plaintext = cbc_dec.decrypt(&ciphertext).unwrap();

        prop_assert_eq!(plaintext, data);
    }

    #[test]
    fn aes256_cbc_roundtrip(
        key in any::<[u8; 32]>(),
        iv in any::<[u8; 16]>(),
        data in block_aligned_data()
    ) {
        let secret_key = SecretBytes::<32>::new(key);
        let nonce = Nonce::<16>::new(iv);

        // Encrypt
        let cipher = Aes256::new(&secret_key);
        let cbc_enc = Cbc::new(cipher, &nonce).unwrap();
        let ciphertext = cbc_enc.encrypt(&data).unwrap();

        // Decrypt
        let cipher = Aes256::new(&secret_key);
        let cbc_dec = Cbc::new(cipher, &nonce).unwrap();
        let plaintext = cbc_dec.decrypt(&ciphertext).unwrap();

        prop_assert_eq!(plaintext, data);
    }

    #[test]
    fn different_keys_produce_different_ciphertexts(
        key1 in any::<[u8; 16]>(),
        key2 in any::<[u8; 16]>(),
        iv in any::<[u8; 16]>(),
        data in block_aligned_data().prop_filter("non-empty data", |d| !d.is_empty())
    ) {
        prop_assume!(key1 != key2);

        let secret_key1 = SecretBytes::<16>::new(key1);
        let secret_key2 = SecretBytes::<16>::new(key2);
        let nonce = Nonce::<16>::new(iv);

        // Encrypt with key1
        let cipher1 = Aes128::new(&secret_key1);
        let cbc1 = Cbc::new(cipher1, &nonce).unwrap();
        let ct1 = cbc1.encrypt(&data).unwrap();

        // Encrypt with key2
        let cipher2 = Aes128::new(&secret_key2);
        let cbc2 = Cbc::new(cipher2, &nonce).unwrap();
        let ct2 = cbc2.encrypt(&data).unwrap();

        prop_assert_ne!(ct1, ct2);
    }

    #[test]
    fn different_ivs_produce_different_ciphertexts(
        key in any::<[u8; 16]>(),
        iv1 in any::<[u8; 16]>(),
        iv2 in any::<[u8; 16]>(),
        data in block_aligned_data().prop_filter("non-empty data", |d| !d.is_empty())
    ) {
        prop_assume!(iv1 != iv2);

        let secret_key = SecretBytes::<16>::new(key);
        let nonce1 = Nonce::<16>::new(iv1);
        let nonce2 = Nonce::<16>::new(iv2);

        // Encrypt with IV1
        let cipher1 = Aes128::new(&secret_key);
        let cbc1 = Cbc::new(cipher1, &nonce1).unwrap();
        let ct1 = cbc1.encrypt(&data).unwrap();

        // Encrypt with IV2
        let cipher2 = Aes128::new(&secret_key);
        let cbc2 = Cbc::new(cipher2, &nonce2).unwrap();
        let ct2 = cbc2.encrypt(&data).unwrap();

        prop_assert_ne!(ct1, ct2);
    }

    #[test]
    fn ciphertext_length_matches_padded_plaintext(
        key in any::<[u8; 16]>(),
        iv in any::<[u8; 16]>(),
        data_len in 1usize..=1000
    ) {
        // Create data of specific length
        let data = vec![0u8; data_len];

        // Calculate expected padded length
        let expected_len = if data_len % 16 == 0 {
            data_len
        } else {
            ((data_len / 16) + 1) * 16
        };

        // Create block-aligned data for encryption
        let mut padded_data = data.clone();
        while padded_data.len() % 16 != 0 {
            padded_data.push(0);
        }

        let secret_key = SecretBytes::<16>::new(key);
        let nonce = Nonce::<16>::new(iv);

        let cipher = Aes128::new(&secret_key);
        let cbc = Cbc::new(cipher, &nonce).unwrap();
        let ciphertext = cbc.encrypt(&padded_data).unwrap();

        prop_assert_eq!(ciphertext.len(), expected_len);
    }
}