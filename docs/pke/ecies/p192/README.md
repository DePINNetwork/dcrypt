# ECIES with P-192 and ChaCha20Poly1305 

This module provides an implementation of the **Elliptic Curve Integrated Encryption Scheme (ECIES)** specifically configured to use the **NIST P-192** elliptic curve.

It serves as a concrete implementation of the `Pke` (Public Key Encryption) trait from `dcrypt-api`, offering a complete, ready-to-use hybrid encryption scheme.

## Cryptographic Details

This implementation combines a set of specific, well-defined cryptographic primitives to ensure security:

*   **Elliptic Curve**: `NIST P-192` (also known as `secp192r1`). The underlying elliptic curve arithmetic is provided by the `dcrypt-algorithms` crate.
*   **Key Derivation Function (KDF)**: `HKDF-SHA256`. The shared secret derived from the ECDH exchange is processed with HKDF using a SHA-256 hash function to produce the symmetric encryption key.
*   **Authenticated Encryption (AEAD)**: `ChaCha20Poly1305`. The plaintext message is encrypted and authenticated using the ChaCha20 stream cipher combined with the Poly1305 authenticator. This provides both confidentiality and integrity.

The full name for this scheme, as returned by the `name()` function, is **`ECIES-P192-HKDF-SHA256-ChaCha20Poly1305`**.

## Provided Types

*   `EciesP192`: The primary, zero-sized struct that acts as the entry point for all operations. It implements the `Pke` trait.
*   `EciesP192PublicKey`: A wrapper for the public key, which consists of a serialized, uncompressed point on the P-192 curve.
*   `EciesP192SecretKey`: A wrapper for the secret key, which consists of a serialized scalar value. This struct implements `Zeroize` to securely clear its contents from memory when it goes out of scope.

## Usage Example

Here is a complete example demonstrating the key generation, encryption, and decryption flow.

```rust
use dcrypt::pke::ecies::p192::EciesP192;
use dcrypt::api::traits::Pke;
use rand::rngs::OsRng; // For a cryptographically secure RNG

fn main() -> Result<(), dcrypt::api::error::Error> {
    // A secure random number generator is essential.
    let mut rng = OsRng;

    // 1. Generate a keypair for the recipient.
    let (public_key, secret_key) = EciesP192::keypair(&mut rng)?;

    // 2. Define the message and optional associated data (AAD).
    // AAD is authenticated along with the ciphertext but is not encrypted.
    let plaintext = b"This is a top secret message.";
    let aad = Some(b"Message metadata".as_slice());

    // 3. Encrypt the plaintext using the recipient's public key.
    // This operation is non-deterministic and creates a new ephemeral key for each call.
    println!("Encrypting...");
    let ciphertext = EciesP192::encrypt(&public_key, plaintext, aad, &mut rng)?;

    // 4. The recipient can now decrypt the ciphertext using their secret key.
    // The same AAD must be provided during decryption.
    println!("Decrypting...");
    let decrypted_plaintext = EciesP192::decrypt(&secret_key, &ciphertext, aad)?;

    // 5. Verify that the decrypted message matches the original.
    assert_eq!(plaintext, decrypted_plaintext.as_slice());

    println!("\nSuccessfully encrypted and decrypted the message!");
    println!("Original:  '{}'", std::str::from_utf8(plaintext).unwrap());
    println!("Decrypted: '{}'", std::str::from_utf8(&decrypted_plaintext).unwrap());

    Ok(())
}
```

## Security Notes

*   NIST P-192 provides a security level of approximately 96 bits. While it is a standardized curve, for new applications requiring long-term security, it is generally recommended to use curves with a higher security level, such as `P-256` (128-bit security) or stronger.
*   This implementation is secure against chosen-ciphertext attacks (IND-CCA2), provided that the underlying cryptographic primitives (`P-192`, `HKDF-SHA256`, `ChaCha20Poly1305`) are not broken.