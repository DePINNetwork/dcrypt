# ECIES with P-384 and ChaCha20Poly1305 

This module provides a concrete implementation of the Elliptic Curve Integrated Encryption Scheme (ECIES) tailored for the NIST P-384 curve.

## Overview

The `EciesP384` struct encapsulates a complete public-key encryption scheme that offers a high level of security. It conforms to the `dcrypt_api::traits::Pke` trait, providing a standard interface for key generation, encryption, and decryption.

This implementation is designed for scenarios requiring approximately 192 bits of security, aligning with the strength of the underlying P-384 curve.

## Cryptographic Primitives

The `EciesP384` scheme is constructed from the following specific cryptographic algorithms:

*   **Elliptic Curve**: **NIST P-384** (also known as `secp384r1`). This curve provides a 192-bit security level.
*   **Key Derivation Function (KDF)**: **HKDF-SHA384**. The Elliptic Curve Diffie-Hellman (ECDH) shared secret is processed by the HMAC-based Key Derivation Function (HKDF) using SHA-384 as the underlying hash function. This is a robust method for deriving a strong symmetric key from the initial shared secret.
*   **Authenticated Encryption with Associated Data (AEAD)**: **AES-256-GCM**. The plaintext is encrypted and authenticated using the Advanced Encryption Standard (AES) with a 256-bit key in Galois/Counter Mode (GCM). AES-256-GCM is a highly secure and widely adopted standard that provides both confidentiality and integrity for the encrypted data.

## Key Details

*   **Public Key (`EciesP384PublicKey`)**: An uncompressed P-384 point, consisting of 97 bytes (1-byte prefix `0x04` + 48-byte x-coordinate + 48-byte y-coordinate).
*   **Secret Key (`EciesP384SecretKey`)**: A P-384 scalar, which is a 48-byte integer. This key is securely handled and zeroized on drop to prevent accidental leakage.

## Usage Example

The following example demonstrates a complete key generation, encryption, and decryption cycle using `EciesP384`.

```rust
use dcrypt::pke::ecies::p384::EciesP384; // Or use dcrypt::pke::EciesP384
use dcrypt::api::traits::Pke;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Generate a new keypair for the recipient.
    println!("Generating P-384 keypair...");
    let (public_key, secret_key) = EciesP384::keypair(&mut rng)?;

    // 2. Define the message and optional associated data (AAD).
    let plaintext = b"This is a highly confidential message for P-384.";
    let aad = Some(b"Message context: Project Phoenix, Q3 Report".as_slice());

    // 3. Encrypt the message using the recipient's public key.
    println!("Encrypting message...");
    let ciphertext = EciesP384::encrypt(&public_key, plaintext, aad, &mut rng)?;

    // 4. Decrypt the message using the recipient's secret key.
    // The same AAD must be provided.
    println!("Decrypting message...");
    let decrypted_plaintext = EciesP384::decrypt(&secret_key, &ciphertext, aad)?;

    // 5. Verify the decrypted message matches the original.
    assert_eq!(plaintext, decrypted_plaintext.as_slice());

    println!("\nSuccess! Decryption was successful and the message is authentic.");
    println!("Plaintext: {}", std::str::from_utf8(plaintext)?);

    Ok(())
}
```

## Testing

The `tests.rs` file for this module contains a comprehensive suite of unit tests to ensure correctness and security, including:
*   Successful key generation.
*   Encrypt-decrypt round trips with and without associated data.
*   Guaranteed failure when decrypting with the wrong secret key.
*   Guaranteed failure when decrypting tampered or corrupted ciphertext.
*   Guaranteed failure when providing the wrong associated data during decryption.
*   Correct handling of empty plaintext.