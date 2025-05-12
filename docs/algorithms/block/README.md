# Block Ciphers and Modes (`algorithms/block`)

This module provides implementations of block cipher algorithms and their modes of operation. Block ciphers are fundamental symmetric key cryptographic primitives that encrypt data in fixed-size blocks.

## Implemented Block Ciphers

1.  **AES (Advanced Encryption Standard) (`aes`)**
    *   **Standard**: FIPS 197
    *   **Variants**:
        *   `Aes128`: 128-bit key, 128-bit block.
        *   `Aes192`: 192-bit key, 128-bit block.
        *   `Aes256`: 256-bit key, 128-bit block.
    *   **Security Notes**:
        *   Implementations aim for constant-time behavior to mitigate timing side-channel attacks.
        *   Uses bitsliced S-box implementations instead of table lookups for software implementations.
        *   Key expansion is performed internally.
    *   **Core Structs**: `Aes128`, `Aes192`, `Aes256`.

## Modes of Operation (`modes`)

Block ciphers themselves can only encrypt a single block of data matching their block size. Modes of operation define how to securely encrypt variable-length messages using a block cipher.

1.  **CBC (Cipher Block Chaining) (`cbc`)**
    *   **Description**: Each block of plaintext is XORed with the previous ciphertext block before being encrypted. An Initialization Vector (IV) is used for the first block.
    *   **Security Notes**:
        *   Requires an unpredictable IV for each encryption.
        *   Encryption is sequential; decryption can be parallelized.
        *   Susceptible to padding oracle attacks if padding is not handled correctly (this implementation requires plaintext to be pre-padded to a multiple of the block size).
    *   **Core Struct**: `Cbc<B: BlockCipher>`

2.  **CTR (Counter Mode) (`ctr`)**
    *   **Description**: Turns a block cipher into a stream cipher. It encrypts successive values of a "counter" (derived from a nonce and a block counter) to produce a keystream, which is then XORed with the plaintext.
    *   **Security Notes**:
        *   Requires a unique nonce for each message encrypted with the same key. The counter part ensures each block within a message uses a unique keystream block.
        *   Encryption and decryption can be parallelized.
        *   Does not require padding.
        *   Provides no message integrity on its own; typically used with a MAC (e.g., in AES-GCM).
    *   **Core Struct**: `Ctr<B: BlockCipher>`

## Key Traits and Types

-   **`BlockCipher` Trait (`algorithms::block::BlockCipher`)**:
    *   Defines the interface for block cipher implementations.
    *   Associated types: `Algorithm` (marker for key/block sizes), `Key`.
    *   Methods: `new`, `encrypt_block`, `decrypt_block`, `generate_key`.
-   **`CipherAlgorithm` Trait (`algorithms::block::CipherAlgorithm`)**:
    *   A marker trait providing compile-time constants for `KEY_SIZE`, `BLOCK_SIZE`, and algorithm `name`.
-   **`algorithms::types::SymmetricKey<A, N>`**: Used for type-safe symmetric keys.
-   **`algorithms::types::Nonce<N>`**: Used for type-safe nonces/IVs, with compatibility traits like `CbcCompatible` and `AesCtrCompatible`.
-   `common::security::SecretBuffer`: Used internally for secure storage of round keys in AES.

## Usage Example (AES-128-CTR)

```rust
use dcrypt_algorithms::block::aes::Aes128;
use dcrypt_algorithms::block::modes::ctr::{Ctr, CounterPosition};
use dcrypt_algorithms::block::BlockCipher; // algorithms internal trait
use dcrypt_algorithms::types::{SymmetricKey, Nonce};
use dcrypt_algorithms::types::algorithms::Aes128 as Aes128Algorithm; // Marker
use dcrypt_algorithms::error::Result;
use rand::rngs::OsRng; // For key/nonce generation

fn aes128_ctr_example() -> Result<()> {
    // Generate key and nonce
    let mut key_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut key_bytes);
    let key = SymmetricKey::<Aes128Algorithm, 16>::new(key_bytes);

    let mut nonce_bytes = [0u8; 16]; // AES-CTR nonce can be full block size
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::<16>::new(nonce_bytes); // AES block size is 16

    // Create AES-128 cipher instance
    let aes_cipher = Aes128::new(&key);

    // Create CTR mode instance
    // For AES-CTR, the counter is typically in the last 4 bytes of the nonce-counter block.
    // The nonce fills the first 12 bytes.
    let mut ctr_cipher = Ctr::with_counter_params(
        aes_cipher,
        &nonce, // Pass the full 16-byte Nonce here
        CounterPosition::Postfix, // Counter in the last few bytes
        4                         // Counter is 4 bytes long
    )?;


    let mut message = *b"This is a test message for CTR mode."; // 32 bytes, 2 blocks
    println!("Original:  {:?}", message);

    // Encrypt
    ctr_cipher.encrypt(&mut message)?;
    println!("Encrypted: {:?}", message);

    // Reset CTR mode for decryption (or create a new instance)
    // Must use the same nonce and initial counter value.
    // Here, seeking to block 0 effectively resets the counter for decryption.
    ctr_cipher.seek(0); // Seek to the beginning of the stream
    ctr_cipher.decrypt(&mut message)?;
    println!("Decrypted: {:?}", message);

    assert_eq!(message, *b"This is a test message for CTR mode.");

    Ok(())
}

// fn main() {
//     aes128_ctr_example().expect("AES-128-CTR example failed");
// }
```

## Security Considerations

-   **Key Secrecy**: Symmetric keys must be kept secret.
-   **IV/Nonce Management**:
-   For CBC mode, IVs must be unpredictable and unique for each encryption with the same key.
-   For CTR mode, nonces must be unique for each message encrypted with the same key. Reusing a nonce/key pair in CTR mode is catastrophic, leading to keystream reuse and loss of confidentiality.
-   **Padding (CBC)**: Plaintext for CBC mode must be padded to a multiple of the block size. This implementation requires the caller to handle padding. Improper padding removal can lead to padding oracle attacks.
-   **Integrity**: CBC and CTR modes, by themselves, do not provide message integrity. If integrity is required, these modes should be combined with a Message Authentication Code (MAC), or an AEAD mode like AES-GCM should be used.