# ECIES with P-521 and ChaCha20Poly1305 

This module provides an implementation of the Elliptic Curve Integrated Encryption Scheme (ECIES) tailored for the **NIST P-521** elliptic curve.

It combines the high security level of the P-521 curve with a strong key derivation function and a modern, high-performance authenticated cipher to provide robust public-key encryption.

## Scheme Details

The `EciesP521` struct implements the `dcrypt_api::traits::Pke` trait using the following set of cryptographic primitives:

| Component | Algorithm | Details |
| :--- | :--- | :--- |
| **Elliptic Curve** | NIST P-521 | Provides a very high level of security, suitable for protecting highly sensitive data long-term. |
| **Key Derivation** | HKDF-SHA512 | The HMAC-based Key Derivation Function (HKDF) is used with SHA-512. The hash function is chosen to match the security strength of the P-521 curve. |
| **Authenticated Encryption** | AES-256-GCM | Advanced Encryption Standard with a 256-bit key in Galois/Counter Mode provides both confidentiality and data integrity. It is widely trusted and highly performant on modern hardware. |
| **Public Key Size** | 133 bytes | `1 (prefix) + 66 (x-coord) + 66 (y-coord)` for an uncompressed point. |
| **Secret Key Size** | 66 bytes | The size of a P-521 scalar. |

## Core Components

*   `EciesP521`: The main struct that provides the ECIES functionality. It is the entry point for key generation, encryption, and decryption operations.
*   `EciesP521PublicKey`: A dedicated type representing a P-521 public key. It is a wrapper around the byte representation of an uncompressed elliptic curve point.
*   `EciesP521SecretKey`: A dedicated type for the P-521 secret key. It wraps the raw scalar bytes and implements the `Zeroize` and `ZeroizeOnDrop` traits to securely wipe the key from memory as soon as it goes out of scope.

## Usage Example

The following example demonstrates a complete key generation, encryption, and decryption roundtrip using `EciesP521`.

```rust
use dcrypt::pke::ecies::p521::EciesP521;
use dcrypt::api::traits::Pke;
use rand::rngs::OsRng; // A cryptographically secure random number generator

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A secure RNG is needed for key generation and encryption.
    let mut rng = OsRng;

    // 1. Generate a keypair for the recipient.
    println!("Generating P-521 keypair...");
    let (public_key, secret_key) = EciesP521::keypair(&mut rng)?;

    // 2. Define the message and optional associated data (AAD).
    let plaintext = b"This is a top-secret message for P-521 ECIES.";
    let aad = Some(b"Message context: Project Chimera, Q4".as_slice());

    // 3. Encrypt the message using the recipient's public key.
    println!("Encrypting message...");
    let ciphertext = EciesP521::encrypt(&public_key, plaintext, aad, &mut rng)?;

    println!("Ciphertext size: {} bytes", ciphertext.len());

    // 4. Decrypt the message using the recipient's secret key.
    // The same AAD must be provided.
    println!("Decrypting message...");
    let decrypted_plaintext = EciesP521::decrypt(&secret_key, &ciphertext, aad)?;

    // 5. Verify the decrypted message matches the original.
    assert_eq!(plaintext, decrypted_plaintext.as_slice());

    println!("\nSuccess! Decryption was successful and the message is authentic.");
    println!("Decrypted content: {}", std::str::from_utf8(&decrypted_plaintext)?);

    Ok(())
}
```

## Security Considerations

*   **Forward Secrecy**: The scheme achieves forward secrecy because a new ephemeral keypair is generated for every encryption. A compromise of the recipient's long-term secret key will not compromise past messages.
*   **Key Security**: The `EciesP521SecretKey` struct automatically clears its memory on drop, reducing the risk of secret key material being exposed in memory dumps or through other side channels.
*   **Integrity and Authenticity**: The use of AES-256-GCM ensures that any tampering with the ciphertext or the associated data (AAD) will be detected during decryption, causing the operation to fail. This prevents a wide range of attacks where an adversary might try to modify an encrypted message.