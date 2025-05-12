# Message Authentication Codes (`algorithms/mac`)

This module implements Message Authentication Code (MAC) algorithms. MACs are used to verify both the integrity and authenticity of a message. They produce a short piece of information (the tag or MAC) using a secret key and the message content. The recipient, possessing the same secret key, can recompute the MAC for the received message and compare it to the received tag to verify the message.

The implementations here prioritize constant-time operations for tag generation and verification to prevent timing attacks against the secret key.

## Implemented MAC Algorithms

1.  **HMAC (Hash-based Message Authentication Code) (`hmac`)**
    *   **Standard**: RFC 2104, FIPS 198-1
    *   **Description**: A MAC constructed from a cryptographic hash function (e.g., SHA-256) and a secret key. It uses two nested hash computations.
    *   **Underlying Hash**: Generic over `H: HashFunction`. Can be used with SHA-256, SHA-512, etc.
    *   **Key Size**: Variable, typically the block size of the hash function, but can be shorter or longer (longer keys are hashed down).
    *   **Tag Size**: Typically the output size of the underlying hash function, but can be truncated.
    *   **Security Notes**: Very widely used and secure when instantiated with a secure hash function. The implementation is designed to be constant-time.
    *   **Core Struct**: `algorithms::mac::hmac::Hmac<H: HashFunction>`

2.  **Poly1305 (`poly1305`)**
    *   **Standard**: RFC 8439 (often used with ChaCha20 in ChaCha20Poly1305 AEAD)
    *   **Description**: A polynomial evaluation MAC. It processes the message in 16-byte blocks, evaluates a polynomial modulo a prime (2^130 - 5), and adds a one-time key (derived from the main key and nonce if used in an AEAD context, or directly from part of the key if used as a standalone MAC).
    *   **Key Size**: 256 bits (32 bytes). This key is split into `r` (16 bytes, clamped) and `s` (16 bytes).
    *   **Tag Size**: 128 bits (16 bytes).
    *   **Security Notes**: Fast and secure. The implementation uses pure Rust limb arithmetic and is constant-time throughout. Poly1305 is a one-time MAC when its `s` key (the final addition part) is used directly. When used in AEADs like ChaCha20Poly1305, the `s` part is typically derived from an encrypted counter block, making it safe for multiple messages under the same main key (but different nonces).
    *   **Core Struct**: `algorithms::mac::poly1305::Poly1305`

## Key Traits and Types

-   **`Mac` Trait (`algorithms::mac::Mac`)**:
    *   Defines the common interface for MAC algorithms.
    *   Associated types: `Key` (fixed-size array), `Tag` (e.g., `Tag<N>`).
    *   Methods: `new`, `update`, `finalize`, `reset`.
    *   Static methods: `compute_tag` (one-shot), `verify_tag` (constant-time verification).
-   **`MacAlgorithm` Trait (`algorithms::mac::MacAlgorithm`)**:
    *   A marker trait providing compile-time constants: `KEY_SIZE`, `TAG_SIZE`, `BLOCK_SIZE`, and algorithm `name`.
-   **`Tag<const N: usize>` (`algorithms::types::Tag`)**:
    *   A type-safe wrapper for MAC tags, ensuring fixed size at compile time.
-   `common::security::SecretBuffer`: Used internally for secure storage of key material (e.g., HMAC's `ipad`/`opad`, Poly1305's `r` and `s`).

## Usage Example (HMAC-SHA256)

```rust
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_algorithms::hash::Sha256; // Underlying hash function
use dcrypt_algorithms::mac::Mac;     // The MAC trait
use dcrypt_algorithms::error::Result;
use dcrypt_algorithms::types::Tag;
use rand::rngs::OsRng; // For key generation
use dcrypt_algorithms::types::RandomGeneration; // For Tag random generation for test (not typical)

fn hmac_sha256_example() -> Result<()> {
    // Generate a random key (HMAC keys can be variable length, often block size of hash)
    let mut key_bytes = [0u8; 32]; // SHA-256 block size is 64, but 32-byte keys are common
    OsRng.fill_bytes(&mut key_bytes);

    let message = b"This is the message to authenticate.";

    // One-shot MAC computation
    let tag1: Tag<32> = Hmac::<Sha256>::compute_tag(&key_bytes, message)?;
    println!("HMAC-SHA256 Tag 1 (one-shot): {}", tag1.to_hex());

    // Incremental MAC computation
    let mut hmac_instance = Hmac::<Sha256>::new(&key_bytes)?;
    hmac_instance.update(b"This is the message ")?;
    hmac_instance.update(b"to authenticate.")?;
    let tag2: Tag<32> = hmac_instance.finalize()?;
    println!("HMAC-SHA256 Tag 2 (incremental): {}", tag2.to_hex());

    assert_eq!(tag1, tag2);

    // Verification (constant-time)
    assert!(Hmac::<Sha256>::verify_tag(&key_bytes, message, tag1.as_ref())?);
    println!("Tag verification successful!");

    // Example of a failed verification
    let mut wrong_tag_bytes = *tag1.as_ref();
    wrong_tag_bytes[0] ^= 0xff; // Flip a bit
    let wrong_tag = Tag::<32>::new(wrong_tag_bytes);

    assert!(!Hmac::<Sha256>::verify_tag(&key_bytes, message, wrong_tag.as_ref())?);
    println!("Verification of tampered tag correctly failed.");

    Ok(())
}

// fn main() {
//     hmac_sha256_example().expect("HMAC-SHA256 example failed");
// }
```

## Security Considerations

-   **Key Secrecy**: The security of a MAC relies entirely on the secrecy of the shared key.
-   **Tag Length**: Do not truncate MAC tags unnecessarily, as this reduces security against forgery.
-   **Constant-Time Verification**: Always use the provided `verify_tag` method (or equivalent constant-time comparison) for comparing MAC tags to prevent timing attacks that could leak information about the tag or key.
-   **One-Time MACs (like raw Poly1305)**: Be aware of the usage context. Raw Poly1305 is a one-time MAC. For multiple messages, it must be used within a construction like ChaCha20Poly1305 that generates unique per-message keys for Poly1305. HMAC is generally safe for multiple messages with the same key.