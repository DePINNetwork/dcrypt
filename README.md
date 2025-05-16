# DCRYPT - Pure Rust Cryptographic Library

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
<!-- TO DO: other badges as appropriate, e.g., build status, crates.io version -->

DCRYPT is a modern, pure Rust cryptographic library designed from the ground up with a focus on security, modularity, and ease of use. It provides a comprehensive suite of both traditional (classical) and post-quantum cryptographic (PQC) algorithms, all implemented entirely in Rust to ensure memory safety and cross-platform compatibility without relying on FFI.

Our mission is to offer robust, audited, and developer-friendly cryptographic tools suitable for a wide range of applications, from embedded systems (`no_std` environments) to high-performance servers.

## Key Features

*   **Pure Rust Implementation**: Ensures memory safety and eliminates the complexities and risks associated with FFI.
*   **Comprehensive Algorithm Support**:
    *   **Symmetric Ciphers**: AES (GCM, CBC, CTR), ChaCha20Poly1305, XChaCha20Poly1305.
    *   **Hash Functions**: SHA-2, SHA-3, SHAKE, BLAKE2, BLAKE3 (as XOF).
    *   **MACs**: HMAC, Poly1305.
    *   **KDFs**: PBKDF2, HKDF, Argon2.
    *   **Key Encapsulation Mechanisms (KEMs)**:
        *   *Traditional*: RSA-KEM, DH, ECDH (P-256, P-384).
        *   *Post-Quantum*: Kyber, NTRU, Saber, McEliece.
    *   **Digital Signatures**:
        *   *Traditional*: Ed25519, ECDSA (P-256, P-384), RSA (PSS, PKCS#1 v1.5), DSA.
        *   *Post-Quantum*: Dilithium, Falcon, SPHINCS+, Rainbow.
    *   **Hybrid Schemes**: Combinations of traditional and PQC algorithms for KEMs and signatures (e.g., ECDH+Kyber KEM, ECDSA+Dilithium Signatures).
*   **Security-First Design**:
    *   **Constant-Time Operations**: Critical components are designed to resist timing side-channel attacks (see [CONSTANT_TIME_POLICY.md](./CONSTANT_TIME_POLICY.md)).
    *   **Secure Memory Handling**: Automatic zeroization of sensitive data (keys, intermediate values) using `zeroize` and custom secure types.
    *   **Type Safety**: Strong typing and Rust's ownership model are leveraged to prevent common cryptographic misuses.
*   **Modular Architecture**: Organized as a Rust workspace with specialized crates for API, common utilities, cryptographic primitives, and high-level algorithm categories.
*   **Cross-Platform & Environment Support**:
    *   Works in `std` and `no_std` (with `alloc`) environments.
    *   Designed with WebAssembly (WASM) compatibility in mind.
*   **Ergonomic API**: Aims for interfaces that are easy to use correctly and hard to misuse, including builder patterns for complex operations.
*   **Extensive Testing**: Includes unit tests, integration tests, and constant-time verification tests, using official test vectors where available.

## Project Structure

DCRYPT is a Rust workspace composed of several crates:

*   **`crates/api`**: Defines the public API traits, core error types, and fundamental data types (e.g., `SecretBytes`, `Key`).
*   **`crates/common`**: Provides shared utilities, especially security primitives like `SecretBuffer`, `EphemeralSecret`, and constant-time comparison helpers.
*   **`crates/internal`**: Contains low-level, non-public utility functions for internal use (e.g., endian conversions, specific constant-time logic).
*   **`crates/params`**: A `no_std` crate centralizing cryptographic parameters and constants for all supported algorithms.
*   **`crates/algorithms`**: The core crate implementing foundational cryptographic primitives (hashes, block ciphers, MACs, AEADs, KDFs, XOFs).
*   **`crates/symmetric`**: High-level APIs for symmetric encryption, including AEAD ciphers and streaming encryption.
*   **`crates/kem`**: Implementations of Key Encapsulation Mechanisms (traditional and PQC).
*   **`crates/sign`**: Implementations of Digital Signature schemes (traditional and PQC).
*   **`crates/hybrid`**: Implementations of hybrid KEMs and signature schemes.
*   **`crates/utils`**: Development utilities (testing helpers, benchmarks, etc.).
*   **`tests`**: A dedicated crate for integration and specialized tests (e.g., constant-time verification).

For detailed documentation on each crate and module, please see the [DCRYPT Documentation](./dcrypt_docs/README.md).

## Quick Start

Add DCRYPT crates to your `Cargo.toml`. For example, to use AES-256-GCM:

```toml
[dependencies]
# For the API traits and core types
dcrypt-api = { path = "crates/api" } # Or from crates.io: "0.1.0"
# For symmetric cipher implementations
dcrypt-symmetric = { path = "crates/symmetric" } # Or from crates.io: "0.1.0"
# For AES keys and algorithm implementations (symmetric depends on this)
dcrypt-algorithms = { path = "crates/algorithms" } # Or from crates.io: "0.1.0"
# For random number generation
rand = "0.8"
# For hex encoding in example
hex = "0.4"
```

## Example: AES-256-GCM Encryption & Decryption

```rust
use dcrypt_symmetric::aes::{Aes256Key, Aes256Gcm, GcmNonce};
use dcrypt_symmetric::cipher::{SymmetricCipher, Aead};
use dcrypt_symmetric::error::Result as SymmetricResult; // Use the crate-specific Result

fn main() -> SymmetricResult<()> {
    // 1. Generate a new AES-256 key
    // In a real application, you'd securely store and manage this key.
    let key = Aes256Key::generate();

    // 2. Create a new AES-256-GCM cipher instance
    let cipher = Aes256Gcm::new(&key)?;

    // 3. Prepare plaintext and optional associated data (AAD)
    let plaintext = b"This is a highly confidential message!";
    let aad = Some(b"Important metadata to authenticate");

    // 4. Generate a unique nonce for this encryption
    // CRITICAL: Nonce must be unique for every encryption with the same key.
    let nonce = Aes256Gcm::generate_nonce();

    // 5. Encrypt the plaintext
    let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!("AAD: {}", String::from_utf8_lossy(aad.unwrap_or_default()));
    println!("Nonce (Base64): {}", nonce.to_string());
    println!("Ciphertext (Hex): {}", hex::encode(&ciphertext));

    // 6. Decrypt the ciphertext
    // The same key, nonce, and AAD must be used for decryption.
    let decrypted_plaintext = cipher.decrypt(&nonce, &ciphertext, aad)?;

    // 7. Verify
    assert_eq!(plaintext, decrypted_plaintext.as_slice());
    println!("Decrypted Plaintext: {}", String::from_utf8_lossy(&decrypted_plaintext));
    println!("AES-256-GCM encryption and decryption successful!");

    Ok(())
}
```

For more examples, including post-quantum KEMs and digital signatures, please see the examples/ directory in the codebase and the documentation for individual crates.

## Security

Security is the paramount design goal of DCRYPT.

* **No unsafe in core primitives (goal)**: We strive to write safe Rust. Where unsafe might be strictly necessary for performance or low-level interaction (e.g., SIMD), it will be rigorously reviewed and minimized.
* **Constant-Time Execution**: Critical cryptographic operations are implemented to be resistant to timing side-channel attacks. See our Constant-Time Policy.
* **Secure Memory Management**: All sensitive data (keys, intermediate states) is handled using types that ensure automatic zeroization on drop.
* **Extensive Testing**: Rigorous testing against official test vectors and statistical analysis for side-channel resistance.
* **Formal Audits (Future Goal)**: We aim to have core components of the library formally audited by security professionals.

**Disclaimer**: Cryptography is complex. While DCRYPT aims for high security, always ensure you understand the security implications of the algorithms and parameters you choose. If in doubt, consult with a cryptography expert.

## Feature Flags

DCRYPT uses feature flags to allow users to tailor the library to their specific needs, especially for no_std environments or to include/exclude specific algorithm families. Common flags include:

* **std (default)**: Enables functionality dependent on the Rust standard library.
* **alloc**: Enables functionality requiring heap allocation (like Vec), for no_std environments that have an allocator.
* **no_std**: For building without the standard library.
* **serde**: Enables serialization/deserialization support for various types using the serde framework.
* **xof**: Enables Extendable Output Functions.

Specific algorithm features (e.g., aes, sha256, kyber) may be available in individual crates to control code size.

Refer to the Cargo.toml files of individual crates for detailed feature flags.

## Further Documentation

Comprehensive documentation for each crate and major module can be found in the docs/ directory.

## License

DCRYPT is distributed under the terms of the Apache License (Version 2.0).

See LICENSE-APACHE for details.

## Contributing

We welcome contributions to DCRYPT! Whether it's reporting issues, submitting pull requests for bug fixes, implementing new features, or improving documentation, your help is appreciated. Please see CONTRIBUTING.md for guidelines on how to contribute.