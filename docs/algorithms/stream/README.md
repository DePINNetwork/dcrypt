# Stream Ciphers (`algorithms/stream`)

This module provides implementations of stream ciphers. Stream ciphers are a type of symmetric key cipher where plaintext digits are combined with a pseudorandom cipher digit stream (keystream), typically using an XOR operation. Each plaintext digit is encrypted one at a time.

## Implemented Stream Ciphers

1.  **ChaCha20 (`chacha`)**
    *   **Standard**: RFC 8439
    *   **Description**: A high-speed stream cipher designed by Daniel J. Bernstein. It operates by encrypting successive counter blocks to generate a keystream.
    *   **Key Size**: 256 bits (32 bytes).
    *   **Nonce Size**: 96 bits (12 bytes).
    *   **Block Size (for keystream generation)**: 512 bits (64 bytes).
    *   **Counter Size**: Typically 32 bits, allowing for 2^32 * 64 bytes (256 GiB) of data per nonce/key pair. Some variants use a 64-bit counter. The implementation here uses a 32-bit counter.
    *   **Security Notes**:
        *   Widely regarded as secure and efficient.
        *   CRITICAL: Requires a unique nonce for every message encrypted with the same key. Nonce reuse leads to catastrophic failure, allowing recovery of XORed plaintexts.
        *   The implementation includes secure handling of the key (`SecretBuffer`) and intermediate ChaCha20 state.
    *   **Core Struct**: `algorithms::stream::chacha::chacha20::ChaCha20`

## Key Traits and Types

-   **`StreamCipher` Trait (`algorithms::stream::StreamCipher`)**:
    *   Defines a common interface for stream cipher implementations.
    *   Constants: `KEY_SIZE`, `NONCE_SIZE`, `BLOCK_SIZE`.
    *   Methods:
        *   `process(&mut self, data: &mut [u8])`: Encrypts or decrypts data in place.
        *   `encrypt(&mut self, data: &mut [u8])`: Alias for `process`.
        *   `decrypt(&mut self, data: &mut [u8])`: Alias for `process`.
        *   `keystream(&mut self, output: &mut [u8])`: Fills the output buffer with keystream bytes.
        *   `reset(&mut self)`: Resets the cipher to its initial state (same key, nonce, initial counter).
        *   `seek(&mut self, position: u64)`: Seeks to a specific byte position in the keystream (by adjusting the block counter).
-   **`algorithms::types::Nonce<N>`**: Used for type-safe nonces, with compatibility traits like `ChaCha20Compatible`.
-   **`algorithms::types::SymmetricKey<A, N>` or `[u8; KEY_SIZE]`**: Used for keys. The `ChaCha20` struct takes `&[u8; CHACHA20_KEY_SIZE]`.
-   `common::security::SecretBuffer`: Used internally by `ChaCha20` for secure key storage.
-   `common::security::EphemeralSecret`: Used by `ChaCha20` for secure handling of the keystream generation state.

## Usage Example (ChaCha20)

```rust
use dcrypt_algorithms::stream::chacha::chacha20::ChaCha20;
use dcrypt_algorithms::stream::StreamCipher; // The StreamCipher trait
use dcrypt_algorithms::types::Nonce;
use dcrypt_algorithms::types::nonce::ChaCha20Compatible; // Marker trait for nonce
use dcrypt_algorithms::error::Result;
use rand::rngs::OsRng; // For key/nonce generation

// Ensure Nonce<12> implements ChaCha20Compatible (it does in algorithms::types::nonce)
struct MyChaCha20Nonce(Nonce<12>);
impl ChaCha20Compatible for MyChaCha20Nonce {}


fn chacha20_example() -> Result<()> {
    // Generate key and nonce
    let mut key_bytes = [0u8; dcrypt_algorithms::stream::chacha::chacha20::CHACHA20_KEY_SIZE];
    OsRng.fill_bytes(&mut key_bytes);

    let mut nonce_bytes = [0u8; dcrypt_algorithms::stream::chacha::chacha20::CHACHA20_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::<12>::new(nonce_bytes); // ChaCha20 uses a 12-byte nonce

    // Create ChaCha20 cipher instance
    // The `new` method expects a reference to a Nonce that implements ChaCha20Compatible
    let mut cipher = ChaCha20::new(&key_bytes, &nonce);

    let mut message = *b"This is a secret message to be encrypted by ChaCha20.";
    println!("Original:  {:?}", String::from_utf8_lossy(&message));

    // Encrypt
    cipher.encrypt(&mut message)?;
    println!("Encrypted: {:?}", hex::encode(&message));

    // To decrypt, reset the cipher (or create a new one with same key, nonce, initial counter)
    // The current API resets to the initial counter provided at construction (which is 0 by default).
    cipher.reset()?;
    // If seeking was used, or a non-zero initial counter, ensure to re-seek or re-initialize.
    // For simple full message encryption/decryption, reset is sufficient.

    cipher.decrypt(&mut message)?;
    println!("Decrypted: {:?}", String::from_utf8_lossy(&message));

    assert_eq!(message, *b"This is a secret message to be encrypted by ChaCha20.");

    // Keystream generation
    let mut keystream_output = [0u8; 10];
    cipher.reset()?; // Reset to get keystream from the beginning
    cipher.keystream(&mut keystream_output)?;
    println!("First 10 keystream bytes: {:?}", hex::encode(&keystream_output));

    Ok(())
}

// fn main() {
//     chacha20_example().expect("ChaCha20 example failed");
// }
```

## Security Considerations

-   **Nonce Uniqueness**: This is the most critical security requirement for stream ciphers. **NEVER** reuse a (key, nonce) pair to encrypt different messages. Doing so will allow an attacker to XOR the two ciphertexts together, cancelling out the keystream and revealing the XOR of the two plaintexts, often leading to full plaintext recovery.
-   **Initial Counter**: While the RFC specifies a 32-bit block counter, some protocols might use a portion of the 96-bit nonce for the initial counter value. The `ChaCha20::with_counter` constructor allows setting an initial counter. Ensure this is managed correctly if not starting from block 0.
-   **Integrity**: Stream ciphers like ChaCha20 provide confidentiality but **not** integrity or authenticity. An attacker can flip bits in the ciphertext, and these changes will propagate to the decrypted plaintext without detection. If integrity/authenticity is required, ChaCha20 should be combined with a MAC (e.g., Poly1305, as in ChaCha20Poly1305 AEAD).