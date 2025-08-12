# AES-GCM Authenticated Encryption

## Overview

This module provides a constant-time, secure implementation of the AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) authenticated encryption with associated data (AEAD) cipher. AES-GCM is a widely-used, high-performance AEAD mode specified in **NIST Special Publication 800-38D**.

It combines the AES block cipher operating in Counter (CTR) mode for encryption with the GHASH function for authentication, providing strong guarantees of both **confidentiality** and **authenticity**.

## Features

*   **AEAD Functionality:** Encrypts plaintext and generates an authentication tag that covers both the plaintext and optional associated data (AD).
*   **Generic Implementation:** The `Gcm<B>` struct is generic over the underlying 128-bit block cipher. It is intended for use with the AES variants provided in this crate:
    *   `Gcm<Aes128>`
    *   `Gcm<Aes192>`
    *   `Gcm<Aes256>`
*   **NIST Compliance:** The implementation is validated against the official NIST Cryptographic Algorithm Validation Program (CAVP) test vectors to ensure correctness and interoperability.
*   **Flexible Nonce Size:** While optimized for the standard 96-bit (12-byte) nonce, the implementation correctly handles other nonce lengths as specified by NIST SP 800-38D.
*   **Variable Tag Length:** Supports customizable authentication tag lengths, though the full 128-bit (16-byte) tag is recommended for maximum security.

## Security

Security is the primary design consideration for this implementation.

*   **Constant-Time Execution:** The core cryptographic operations, especially the GHASH multiplication and the final tag comparison, are implemented to be constant-time. Tag verification uses `subtle::ConstantTimeEq` to prevent timing side-channel attacks that could leak information about the tag's validity.
*   **Secure Memory Handling:** The internal GHASH key (`H`) and the AES round keys are stored in a `SecretBuffer`, which ensures they are securely zeroed from memory when no longer in use, preventing accidental key leakage.
*   **Robust API:** The API is designed around the `SymmetricCipher` trait, using a builder pattern that guides the user to provide all necessary components (like the nonce) before an operation can be executed, reducing the risk of misuse.

## Usage

### Encryption and Decryption with AES-128-GCM

The following example demonstrates a complete encrypt-decrypt cycle using `Gcm<Aes128>`.

```rust
use dcrypt::algorithms::aead::gcm::Gcm;
use dcrypt::algorithms::block::Aes128;
use dcrypt::algorithms::types::{Nonce, SecretBytes};
use dcrypt::api::traits::SymmetricCipher;
use dcrypt::api::traits::symmetric::{EncryptOperation, DecryptOperation};

// 1. Setup the key, nonce, plaintext, and associated data.
let key = SecretBytes::new([42u8; 16]);
let nonce = Nonce::<12>::new([1u8; 12]); // A 96-bit (12-byte) nonce is standard.
let plaintext = b"this is a secret message that needs protection";
let associated_data = b"unencrypted but authenticated metadata";

// 2. Create the AES-128 block cipher instance.
let aes_encrypt = Aes128::new(&key);

// 3. Create the GCM instance for encryption.
let gcm_encrypt = Gcm::new(aes_encrypt, &nonce).unwrap();

// 4. Encrypt the data using the builder pattern.
// The `encrypt()` method on the SymmetricCipher trait returns an EncryptOperation builder.
let ciphertext_obj = gcm_encrypt
    .encrypt()
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .encrypt(plaintext)
    .unwrap();

// The resulting object contains the ciphertext with the authentication tag appended.
println!("AES-GCM Ciphertext (hex): {}", hex::encode(ciphertext_obj.as_ref()));

// 5. For decryption, create a new cipher instance.
let aes_decrypt = Aes128::new(&key);
let gcm_decrypt = Gcm::new(aes_decrypt, &nonce).unwrap();

// 6. Decrypt the data. This will fail if the ciphertext or AAD was tampered with.
let decrypted_payload = gcm_decrypt
    .decrypt()
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .decrypt(&ciphertext_obj)
    .unwrap();

assert_eq!(decrypted_payload, plaintext);
println!("Decryption successful and data verified!");
```

### Security Considerations

#### Nonce (IV) Uniqueness

**CRITICAL:** The security of GCM relies on the uniqueness of the nonce for every encryption operation performed with the same key. **Never reuse a nonce with the same key.** Reusing a nonce can lead to a catastrophic failure of confidentiality and authenticity. It is recommended to generate nonces using a cryptographically secure random number generator or a counter-based scheme.

#### Tag Length

While this implementation supports tag lengths from 1 to 16 bytes via `Gcm::new_with_tag_len`, the full 16-byte (128-bit) tag is strongly recommended. Using shorter tags significantly reduces the security against forgery attacks and should only be done if required by a specific protocol or for performance-critical applications where the security trade-off is acceptable.

## `no_std` Support

This module is compatible with `no_std` environments but requires an allocator. To use it in a `no_std` project, enable the `alloc` and `aead` features in your `Cargo.toml`.

```toml
[dependencies.dcrypt-algorithms]
version = "0.12.0-beta.1"
default-features = false
features = ["alloc", "aead"]
```