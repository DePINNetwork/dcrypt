# Symmetric Cryptography (`symmetric`)

The `symmetric` crate provides high-level APIs for symmetric encryption algorithms, focusing on Authenticated Encryption with Associated Data (AEAD) schemes. It builds upon the cryptographic primitives implemented in the `dcrypt-algorithms` crate, offering more ergonomic interfaces, key management utilities, and streaming capabilities.

## Key Features

-   **High-Level AEAD Ciphers**: Provides ready-to-use implementations of common AEAD schemes.
-   **Secure Key and Nonce Types**: Uses strongly-typed wrappers for keys and nonces to enhance safety and prevent misuse.
-   **Key Derivation**: Includes helper functions for deriving cryptographic keys from passwords.
-   **Ciphertext Packaging**: Offers structures to bundle ciphertexts with their nonces for easier storage and transmission.
-   **Streaming Encryption/Decryption**: Supports memory-efficient processing of large files or data streams.
-   **Error Handling**: Uses a dedicated `Error` type (`symmetric::error::Error`) that integrates with the broader DCRYPT error system.

## Core Modules and Functionality

1.  **AEAD Ciphers (`aead`)**:
    *   **ChaCha20Poly1305 (`aead::chacha20poly1305`)**:
        *   `ChaCha20Poly1305Cipher`: Implements RFC 8439.
        *   `XChaCha20Poly1305Cipher`: Implements the extended nonce (24-byte) variant.
        *   Types: `ChaCha20Poly1305Key`, `ChaCha20Poly1305Nonce` (12-byte), `XChaCha20Poly1305Nonce` (24-byte).
        *   `ChaCha20Poly1305CiphertextPackage`: Bundles nonce and ciphertext.
        *   Key derivation: `derive_chacha20poly1305_key` using PBKDF2-HMAC-SHA256.
    *   **AES-GCM (`aead::gcm`)**:
        *   `Aes128Gcm`: AES-128 in GCM mode.
        *   `Aes256Gcm`: AES-256 in GCM mode.
        *   Types: `Aes128Key`, `Aes256Key` (from `symmetric::aes::keys`), `GcmNonce` (12-byte).
        *   `AesCiphertextPackage`: Bundles nonce and ciphertext.

2.  **AES Key Management (`aes::keys`)**:
    *   Defines `Aes128Key` and `Aes256Key` types with secure generation and serialization.
    *   Provides `derive_aes128_key` and `derive_aes256_key` using PBKDF2-HMAC-SHA256.
    *   `generate_salt` helper for KDFs.

3.  **Cipher Traits (`cipher.rs`)**:
    *   `SymmetricCipher`: Base trait for symmetric ciphers, defining `new(key)` and `name()`.
    *   `Aead`: Extends `SymmetricCipher` for AEAD schemes, adding `encrypt`, `decrypt`, and `generate_nonce` methods.

4.  **Streaming API (`streaming`)**:
    *   **ChaCha20Poly1305 Streaming (`streaming::chacha20poly1305`)**:
        *   `ChaCha20Poly1305EncryptStream<W: Write>`
        *   `ChaCha20Poly1305DecryptStream<R: Read>`
        *   Manages chunking of data and derivation of unique nonces per chunk from a base nonce.
    *   **AES-GCM Streaming (`streaming::gcm`)**:
        *   `Aes128GcmEncryptStream<W: Write>`, `Aes128GcmDecryptStream<R: Read>`
        *   `Aes256GcmEncryptStream<W: Write>`, `Aes256GcmDecryptStream<R: Read>`
        *   Similar chunking and per-chunk nonce derivation strategy as ChaCha20Poly1305 streaming.
    *   **Traits**:
        *   `StreamingEncrypt<W: Write>`: Defines `write` and `finalize`.
        *   `StreamingDecrypt<R: Read>`: Defines `read`.

5.  **Error Handling (`error`)**:
    *   Defines `symmetric::error::Error` with variants like `Primitive`, `Stream`, `Format`, `KeyDerivation`.
    *   Includes validation utilities in `symmetric::error::validate`.

## Usage Examples

### Standard AEAD Encryption (ChaCha20Poly1305)

```rust
use dcrypt_symmetric::aead::chacha20poly1305::{
    ChaCha20Poly1305Cipher, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce
};
use dcrypt_symmetric::cipher::{SymmetricCipher, Aead};
use dcrypt_symmetric::error::Result;

fn chacha_aead_example() -> Result<()> {
    let key = ChaCha20Poly1305Key::generate();
    let cipher = ChaCha20Poly1305Cipher::new(&key)?;

    let plaintext = b"This is a highly secret message!";
    let aad = Some(b"Additional authenticated data");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();

    let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;
    println!("Ciphertext (hex): {}", hex::encode(&ciphertext));

    let decrypted_plaintext = cipher.decrypt(&nonce, &ciphertext, aad)?;
    assert_eq!(plaintext, decrypted_plaintext.as_slice());
    println!("Decryption successful!");

    Ok(())
}
```

### Streaming Encryption (AES-128-GCM)

```rust
use dcrypt_symmetric::aes::Aes128Key;
use dcrypt_symmetric::streaming::gcm::Aes128GcmEncryptStream;
use dcrypt_symmetric::streaming::StreamingEncrypt; // Trait for write/finalize
use dcrypt_symmetric::error::Result;
use std::io::Cursor; // For an in-memory writer example

fn streaming_aes_gcm_example() -> Result<()> {
    let key = Aes128Key::generate();
    let aad = Some(b"Streaming AAD");

    let mut encrypted_output = Cursor::new(Vec::new()); // Write to a Vec<u8>

    // Create encrypt stream
    let mut enc_stream = Aes128GcmEncryptStream::new(&mut encrypted_output, &key, aad)?;

    enc_stream.write(b"This is the first part of a large dataset.")?;
    enc_stream.write(b"And this is the second part.")?;
    // ... more writes ...

    // Finalize the stream
    let _writer = enc_stream.finalize()?; // Finalizes and returns the writer

    let ciphertext_with_header = encrypted_output.into_inner();
    println!("Streaming AES-GCM produced {} bytes.", ciphertext_with_header.len());
    // Note: ciphertext_with_header includes the base_nonce and chunk metadata.
    // Decryption would use Aes128GcmDecryptStream.

    Ok(())
}
```

## Security Design

-   **Nonce Management**: Streaming APIs automatically manage per-chunk nonces derived from an initial base nonce and a counter to ensure nonce uniqueness for each block processed by the underlying primitive.
-   **Key Zeroization**: Key types like `ChaCha20Poly1305Key` and `Aes128Key` implement `Zeroize` and `ZeroizeOnDrop`.
-   **Primitive Reliance**: Security ultimately relies on the correctness and constant-time properties of the underlying implementations in `dcrypt-algorithms`.
-   **Error Propagation**: Uses a local `Result` type that can be converted to/from `api::Error` and `algorithms::error::Error`.

This crate provides a user-friendly and secure layer for common symmetric encryption tasks.