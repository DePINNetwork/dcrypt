# DCRYPT: A Modern, High-Assurance Cryptographic Library for Rust

[![Crates.io](https://img.shields.io/crates/v/dcrypt.svg?style=flat-square)](https://crates.io/crates/dcrypt)
[![Docs.rs](https://img.shields.io/docsrs/dcrypt?style=flat-square)](https://docs.rs/dcrypt)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/DePINNetwork/dcrypt/rust.yml?branch=main&style=flat-square)](https://github.com/DePINNetwork/dcrypt/actions)

**dcrypt** is a pure Rust software-only cryptographic library for DePIN Network's Web4 infrastructure framework providing both traditional and post-quantum cryptography. Designed with emphasis on security, modularity, performance, and usability, dcrypt eliminates foreign function interfaces (FFI) ensuring memory safety and cross-platform compatibility.

## Key Principles

*   **Pure Rust & Memory Safe**: Implemented entirely in Rust without FFI, preventing entire classes of memory-related bugs and ensuring seamless portability.
*   **Security-First Design**: Prioritizes resistance to side-channel attacks through constant-time execution for critical operations and secure memory handling with automatic zeroization of sensitive data.
*   **Comprehensive & Modern**: Provides a full suite of traditional (AES-GCM, SHA-2, ECDH, Ed25519) and post-quantum (Kyber, Dilithium) algorithms, ready for the next generation of secure applications.
*   **Modular & Ergonomic API**: A clean, layered architecture with high-level, easy-to-use APIs for common tasks like authenticated encryption, password hashing, and digital signatures.
*   **`no_std` & Cross-Platform**: Fully compatible with `no_std` environments (with `alloc`), making it ideal for everything from embedded devices and IoT to high-performance web servers.

## Quick Start

Add `dcrypt` and `rand` to your project's `Cargo.toml`:

```toml
[dependencies]
# This assumes a future top-level 'dcrypt' crate.
# For now, you would depend on the specific crates like `dcrypt-symmetric`.
# dcrypt = "0.13.0" 
rand = "0.8"
```

### Example 1: Authenticated Encryption (AES-256-GCM)

Securely encrypt data with authentication to protect against tampering.

```rust
use dcrypt::symmetric::{Aes256Gcm, Aes256Key, Aead, SymmetricCipher, Result};

fn main() -> Result<()> {
    // 1. Generate a new, random key for AES-256-GCM.
    let key = Aes256Key::generate();

    // 2. Create a new cipher instance with the key.
    let cipher = Aes256Gcm::new(&key)?;

    let plaintext = b"this is a very secret message";
    let associated_data = b"metadata"; // Optional: authenticated but not encrypted

    // 3. Generate a random nonce. MUST be unique for each encryption with the same key.
    let nonce = Aes256Gcm::generate_nonce();

    // 4. Encrypt the data.
    println!("Encrypting: '{}'", String::from_utf8_lossy(plaintext));
    let ciphertext = cipher.encrypt(&nonce, plaintext, Some(associated_data))?;

    // 5. Decrypt the data.
    let decrypted_plaintext = cipher.decrypt(&nonce, &ciphertext, Some(associated_data))?;
    println!("Decrypted: '{}'", String::from_utf8_lossy(&decrypted_plaintext));

    // 6. Verify the result.
    assert_eq!(plaintext, &decrypted_plaintext[..]);
    println!("\nAES-256-GCM roundtrip successful!");

    Ok(())
}
```

### Example 2: Password Hashing & Verification (Argon2)

Securely hash user passwords for storage using the state-of-the-art Argon2id algorithm.

```rust
use dcrypt::kdf::{Argon2, PasswordHash, PasswordHashFunction, Result};
use dcrypt::types::SecretBytes;
use std::str::FromStr;

fn main() -> Result<()> {
    let argon2 = Argon2::<16>::new(); // Default Argon2id, salt size 16
    let password = SecretBytes::<32>::new(*b"a-very-secure-password!         ");

    // 1. Hash a new password. This generates a random salt.
    let password_hash = argon2.hash_password(&password)?;

    // 2. The result is a PHC format string, safe to store in your database.
    let hash_string = password_hash.to_string();
    println!("Stored Password Hash: {}", hash_string);

    // --- Later, during login ---

    // 3. Parse the stored hash string.
    let parsed_hash = PasswordHash::from_str(&hash_string)?;

    // 4. Verify the password against the parsed hash.
    // This is a constant-time comparison to prevent timing attacks.
    assert!(argon2.verify(&password, &parsed_hash)?);

    println!("\nPassword verified successfully!");

    // Verification with the wrong password will fail.
    let wrong_password = SecretBytes::<32>::new(*b"incorrect-password...           ");
    assert!(!argon2.verify(&wrong_password, &parsed_hash)?);
    println!("Verification with wrong password failed, as expected.");

    Ok(())
}
```

## Available Algorithms

DCRYPT provides a broad range of cryptographic primitives:

| Category | Algorithms |
| :--- | :--- |
| **AEAD Ciphers** | `AES-GCM`, `ChaCha20-Poly1305`, `XChaCha20-Poly1305` |
| **Hash Functions** | `SHA-2`, `SHA-3`, `BLAKE2` |
| **XOFs** | `SHAKE`, `BLAKE3` |
| **Password Hashing** | `Argon2id` (default), `Argon2i`, `Argon2d` |
| **Key Derivation** | `HKDF`, `PBKDF2` |
| **Digital Signatures** | `ECDSA` (P-256, P-384), `Ed25519` |
| **Post-Quantum Sigs** | `Dilithium` |
| **KEMs** | `ECDH` (P-256, P-384, etc.) |
| **Post-Quantum KEMs**| `Kyber` |
| **Hybrid Schemes** | `ECDH+Kyber` (KEM), `ECDSA+Dilithium` (Signature) |

## Project Architecture

The `dcrypt` library is organized as a workspace with several specialized crates to ensure a clean separation of concerns:

*   **`api`**: Defines the core public traits, error handling, and fundamental types.
*   **`common`**: Provides shared security primitives, such as secure memory wrappers.
*   **`internal`**: Low-level, non-public utilities for constant-time operations.
*   **`params`**: A `no_std` crate centralizing cryptographic parameters and constants.
*   **`algorithms`**: The core cryptographic engine with low-level implementations of all primitives.
*   **`symmetric`**: High-level APIs for symmetric ciphers, including key management and streaming.
*   **`kem`**: Implementations of Key Encapsulation Mechanisms (KEMs).
*   **`sign`**: Implementations of Digital Signature schemes.
*   **`pke`**: Implementations of Public Key Encryption (PKE) schemes like ECIES.
*   **`hybrid`**: Ready-to-use hybrid schemes combining classical and post-quantum algorithms.
*   **`tests`**: Integration tests, constant-time verification, and test vectors.

## Security Philosophy

Security is the primary design driver for DCRYPT.

*   **Constant-Time Execution**: Primitives handling secret data (e.g., key operations, signature verification) are implemented to execute in constant time, mitigating a broad class of timing side-channel attacks.
*   **Secure Memory Handling**: Sensitive data like keys and intermediate cryptographic state are handled using secure memory types that automatically zero their contents when they go out of scope, preventing accidental data leakage from memory.
*   **Type Safety**: We leverage Rust's powerful type system to enforce cryptographic properties at compile time. For example, a key for `AES-256` cannot be accidentally used with a `ChaCha20` cipher, preventing common API misuse.
*   **No Unsafe Code in Primitives**: The core cryptographic logic is written in safe Rust, eliminating the risks associated with FFI and manual memory management.

## Feature Flags

DCRYPT uses feature flags to allow you to tailor the build for your specific needs, helping to minimize binary size.

*   `std` (default): Enables functionality requiring the Rust standard library.
*   `alloc`: For `no_std` environments that have a heap allocator.
*   `serde`: Enables serialization and deserialization for various types via the Serde framework.
*   **Algorithm Flags**: Granular flags like `hash`, `aead`, `kdf`, `sign`, `kem`, `post-quantum`, and `traditional` allow you to include only the cryptographic families you need.

## License

This project is licensed under the **Apache License, Version 2.0**.