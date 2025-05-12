# AEAD Ciphers (`algorithms/aead`)

This module implements Authenticated Encryption with Associated Data (AEAD) schemes. AEAD ciphers provide confidentiality, integrity, and authenticity for encrypted messages. They ensure that the data is not only unreadable to unauthorized parties but also that it has not been tampered with.

The implementations here focus on the core cryptographic logic and are designed with constant-time execution for critical parts to resist timing side-channel attacks.

## Implemented AEAD Schemes

1.  **ChaCha20Poly1305 (`chacha20poly1305`)**
    *   **Standard**: RFC 8439
    *   **Description**: Combines the ChaCha20 stream cipher with the Poly1305 message authentication code.
    *   **Key Size**: 256 bits (32 bytes).
    *   **Nonce Size**: 96 bits (12 bytes).
    *   **Tag Size**: 128 bits (16 bytes).
    *   **Security Notes**:
        *   Provides strong AEAD security.
        *   Constant-time implementation for Poly1305 tag computation and comparison.
        *   Relies on unique nonces for each encryption with the same key.
    *   **Core Struct**: `algorithms::aead::chacha20poly1305::ChaCha20Poly1305`

2.  **XChaCha20Poly1305 (`xchacha20poly1305`)**
    *   **Standard**: Extension of RFC 8439, common construction.
    *   **Description**: An extension of ChaCha20Poly1305 that uses an extended 192-bit (24-byte) nonce. This larger nonce size significantly reduces the probability of nonce reuse, especially in distributed systems or when nonces are generated randomly.
    *   **Key Size**: 256 bits (32 bytes).
    *   **Nonce Size**: 192 bits (24 bytes). The first 16 bytes are used with HChaCha20 to derive a subkey, and the remaining 8 bytes (prepended with 4 zero bytes) form the 12-byte nonce for ChaCha20Poly1305.
    *   **Tag Size**: 128 bits (16 bytes).
    *   **Security Notes**:
        *   Offers improved nonce misuse resistance compared to ChaCha20Poly1305.
        *   Builds upon the security of ChaCha20Poly1305.
    *   **Core Struct**: `algorithms::aead::xchacha20poly1305::XChaCha20Poly1305`

3.  **AES-GCM (`gcm`)**
    *   **Standard**: NIST Special Publication 800-38D.
    *   **Description**: Combines AES in Counter (CTR) mode for encryption with the GHASH algorithm for authentication.
    *   **Supported AES Variants**: AES-128, AES-256 (depending on the block cipher `B` provided to `Gcm<B>`).
    *   **Nonce Size**: Typically 96 bits (12 bytes) is recommended for performance and security, but other sizes are permissible.
    *   **Tag Size**: Typically 128 bits (16 bytes), but can be truncated (though not recommended below 96 bits).
    *   **Security Notes**:
        *   Widely adopted and secure AEAD scheme.
        *   The `GHASH` implementation (`algorithms::aead::gcm::ghash`) is designed to be constant-time.
        *   Requires unique nonces for each encryption with the same key. Nonce reuse can be catastrophic.
    *   **Core Struct**: `algorithms::aead::gcm::Gcm<B: BlockCipher>`

## Key Traits and Types

-   `api::traits::AuthenticatedCipher`: A marker trait implemented by AEAD ciphers, defining `TAG_SIZE` and `ALGORITHM_ID`.
-   `api::traits::SymmetricCipher`: Defines the general interface for symmetric ciphers, including key/nonce generation and encryption/decryption operations using a builder pattern. AEAD ciphers in this module implement this.
-   `algorithms::types::Nonce<N>`: Used for type-safe nonces.
-   `algorithms::types::Tag<N>`: Used for type-safe authentication tags.
-   `algorithms::types::SecretBytes<N>`: For secure key storage.
-   `common::security::SecretBuffer<N>`: Used internally for secure handling of key material.

## Usage

These AEAD primitives are typically wrapped by higher-level APIs in the `dcrypt-symmetric` crate for more ergonomic use. However, they can be used directly.

### Example: Direct ChaCha20Poly1305 Usage

```rust
use dcrypt_algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt_algorithms::types::{Nonce, SecretBytes};
use dcrypt_algorithms::error::Result;
use rand::rngs::OsRng; // For key/nonce generation
use dcrypt_api::traits::SymmetricCipher; // For generate_key/nonce

fn direct_chacha20poly1305_example() -> Result<()> {
    // Generate key and nonce using SymmetricCipher trait methods
    let key_sb = ChaCha20Poly1305::generate_key(&mut OsRng)?; // Returns SecretBytes
    let nonce_obj = ChaCha20Poly1305::generate_nonce(&mut OsRng)?; // Returns Nonce

    // Convert SecretBytes to a fixed-size array for ChaCha20Poly1305::new
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_sb.as_ref());

    let cipher = ChaCha20Poly1305::new(&key_array);

    let plaintext = b"Authenticated and encrypted message";
    let aad = Some(b"Additional data to authenticate");

    // Encrypt
    // The encrypt/decrypt methods in algorithms::aead::chacha20poly1305
    // are for the raw nonce array. We'll use the SymmetricCipher trait methods for typed Nonce.
    let ciphertext_package = cipher.encrypt()
        .with_nonce(&nonce_obj)
        .with_aad(aad.unwrap_or_default())
        .encrypt(plaintext)
        .map_err(dcrypt_algorithms::error::Error::from)?; // Convert CoreError to algorithms::Error


    println!("Ciphertext (hex): {}", hex::encode(ciphertext_package.as_ref()));

    // Decrypt
    let decrypted_plaintext = cipher.decrypt()
        .with_nonce(&nonce_obj)
        .with_aad(aad.unwrap_or_default())
        .decrypt(&ciphertext_package)
        .map_err(dcrypt_algorithms::error::Error::from)?;


    assert_eq!(plaintext, decrypted_plaintext.as_slice());
    println!("Decryption successful!");

    Ok(())
}
```
*(Note: The example above illustrates direct usage. The `api::SymmetricCipher` trait provides a more structured way to use these, as shown in `ChaCha20Poly1305::encrypt()`.)*

## Security Considerations

-   **Nonce Uniqueness**: CRITICAL. Never reuse a nonce with the same key for any AEAD scheme. Nonce reuse can lead to a complete loss of confidentiality and authenticity.
-   **Tag Truncation**: While some AEAD schemes (like GCM) allow tag truncation, it is generally not recommended as it weakens the integrity/authenticity guarantees. This library defaults to full tag sizes.
-   **Key Management**: Secure generation, storage, and handling of keys are paramount. Keys are typically wrapped in `SecretBytes` or `SecretBuffer`.