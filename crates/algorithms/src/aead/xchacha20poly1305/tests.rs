// dcrypt-primitives/src/aead/xchacha20poly1305/tests.rs
use super::*;
use crate::types::Nonce;

#[test]
fn test_xchacha20poly1305() {
    // Simple test for XChaCha20Poly1305
    let key = [0x42; CHACHA20POLY1305_KEY_SIZE];
    let nonce_bytes = [0x24; XCHACHA20POLY1305_NONCE_SIZE];

    // Create the Nonce object from the byte array
    let nonce = Nonce::<XCHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);

    let plaintext = b"Extended nonce allows for random nonces";

    let xchacha = XChaCha20Poly1305::new(&key);

    // Encrypt - now returns Result<Vec<u8>> so we need to expect/unwrap it
    let ciphertext = xchacha
        .encrypt(&nonce, plaintext, None)
        .expect("Encryption failed");

    // Decrypt
    let decrypted = xchacha
        .decrypt(&nonce, &ciphertext, None)
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}
