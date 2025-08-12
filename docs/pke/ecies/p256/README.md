# ECIES with P-256 and ChaCha20Poly1305 

This module provides a concrete implementation of the Elliptic Curve Integrated Encryption Scheme (ECIES) using the **NIST P-256** (also known as `secp256r1` or `prime256v1`) curve.

It combines the P-256 elliptic curve with a robust set of modern cryptographic primitives to deliver a secure and efficient public-key encryption system. This implementation adheres to the `dcrypt_api::traits::Pke` trait, ensuring a consistent and predictable interface.

## Cryptographic Scheme

The `EciesP256` struct implements the following specific cryptographic scheme:

| Component | Primitive Used |
| :--- | :--- |
| **Elliptic Curve** | NIST P-256 |
| **Key Derivation** | HKDF with SHA-256 (HKDF-SHA256) |
| **Authenticated Encryption** | ChaCha20Poly1305 |

The full name for this scheme is **`ECIES-P256-HKDF-SHA256-ChaCha20Poly1305`**.

## Key Structures

This module defines two main structures for handling cryptographic keys:

*   `EciesP256PublicKey`: A wrapper for the public key. It internally stores the 65-byte uncompressed representation of an elliptic curve point (`0x04 || x-coordinate || y-coordinate`).

*   `EciesP256SecretKey`: A wrapper for the secret key. It holds the 32-byte scalar that constitutes the private key. For enhanced security, this struct implements the `Zeroize` and `ZeroizeOnDrop` traits, which securely erase the key material from memory when it goes out of scope.

## `Pke` Trait Implementation

The core of this module is the `EciesP256` struct, which provides the main functionality by implementing the `Pke` trait. This offers a standard set of operations:

*   `keypair()`: Generates a new `(EciesP256PublicKey, EciesP256SecretKey)` pair.
*   `encrypt()`: Encrypts a plaintext message using the recipient's public key.
*   `decrypt()`: Decrypts a ciphertext using the recipient's secret key.

## Usage Example

Here is a complete example demonstrating the key generation, encryption, and decryption roundtrip with `EciesP256`.

```rust
use dcrypt::pke::ecies::p256::{EciesP256, EciesP256PublicKey, EciesP256SecretKey};
use dcrypt::api::traits::Pke;
use rand::rngs::OsRng;

// A cryptographically secure random number generator is required.
let mut rng = OsRng;

// 1. Generate a new keypair for the recipient.
let (public_key, secret_key): (EciesP256PublicKey, EciesP256SecretKey) =
    EciesP256::keypair(&mut rng).expect("Keypair generation failed");

// 2. Define the message and optional associated data (AAD).
let plaintext = b"This is a highly confidential message.";
let aad = Some(b"Message context".as_slice());

// 3. Encrypt the plaintext using the recipient's public key.
//    A new ephemeral key is generated for this specific encryption.
let ciphertext = EciesP256::encrypt(&public_key, plaintext, aad, &mut rng)
    .expect("Encryption failed");

// 4. The recipient decrypts the ciphertext with their secret key.
//    The same AAD must be provided to pass the integrity check.
let decrypted_plaintext = EciesP256::decrypt(&secret_key, &ciphertext, aad)
    .expect("Decryption failed");

// 5. Verify the result.
assert_eq!(plaintext, decrypted_plaintext.as_slice());

println!("Successfully encrypted and decrypted the message!");
```

## Security Design

This implementation includes several key security features:

*   **Ephemeral Keys**: For each encryption, a new, single-use elliptic curve keypair is generated. The public part of this key is sent with the ciphertext, while the private part is used for the ECDH key exchange and then immediately discarded. This ensures **forward secrecy**, meaning that a compromise of the recipient's long-term secret key will not compromise past encrypted messages.

*   **Authenticated Encryption**: The use of `ChaCha20Poly1305` as the AEAD cipher provides both confidentiality (the message is unreadable) and integrity/authenticity (the message cannot be undetectably altered). Any tampering with the ciphertext or providing incorrect AAD during decryption will cause the operation to fail, preventing attacks that rely on modifying encrypted data.

*   **Secure Error Handling**: The `decrypt` function is designed to be constant-time where possible and to return a single, generic `DecryptionFailed` error for any cryptographic failure (e.g., invalid key, tampered ciphertext, incorrect AAD). This helps prevent cryptographic oracle attacks, where an attacker could otherwise gain information about the secret key by analyzing different error types.