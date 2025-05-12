# DCRYPT Algorithms (`algorithms`)

The `algorithms` crate is the heart of the DCRYPT library, providing foundational implementations of various cryptographic primitives. It is designed with a strong emphasis on security, particularly constant-time execution for operations involving secret data, and robust memory safety through the use of Rust's ownership model and specialized secure types.

This crate serves as the building block for higher-level cryptographic functionalities provided by other crates in the DCRYPT workspace, such as `dcrypt-symmetric`, `dcrypt-kem`, and `dcrypt-sign`.

## Key Features

-   **Pure Rust Implementations**: All algorithms are written entirely in Rust.
-   **Constant-Time Focus**: Critical operations are designed to be resistant to timing side-channel attacks, adhering to the project's [Constant-Time Policy](../../CONSTANT_TIME_POLICY.md).
-   **Secure Memory Handling**: Utilizes types like `SecretBuffer` from `dcrypt-common` for keys and sensitive intermediate values, ensuring they are zeroized on drop.
-   **Comprehensive Test Coverage**: Algorithms are tested against official test vectors (e.g., NIST, RFCs) where available.
-   **Modular Design**: Cryptographic primitives are organized into distinct sub-modules.
-   **Type Safety**: Leverages Rust's type system, including generic types like `Nonce<N>`, `Tag<N>`, `Digest<N>`, and `SymmetricKey<A, N>` to enforce correct usage at compile time.

## Modules and Functionality

The `algorithms` crate is organized into the following main sub-modules:

-   **`dcrypt_docs/algorithms/aead/README.md`**: Authenticated Encryption with Associated Data (AEAD) schemes.
    -   ChaCha20Poly1305 (RFC 8439)
    -   XChaCha20Poly1305 (extended nonce)
    -   AES-GCM (NIST SP 800-38D)
-   **`dcrypt_docs/algorithms/block/README.md`**: Block cipher algorithms and modes of operation.
    -   AES (AES-128, AES-192, AES-256 based on FIPS 197) with bitsliced S-Boxes.
    -   Modes: CBC, CTR.
-   **`dcrypt_docs/algorithms/error/README.md`**: Custom error types and validation utilities specific to this crate.
-   **`dcrypt_docs/algorithms/hash/README.md`**: Cryptographic hash functions.
    -   SHA-1 (deprecated, for compatibility)
    -   SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512 based on FIPS 180-4)
    -   SHA-3 family (SHA3-224, SHA3-256, SHA3-384, SHA3-512 based on FIPS 202)
    -   SHAKE (fixed-output versions: SHAKE128, SHAKE256)
    -   BLAKE2 (BLAKE2b, BLAKE2s based on RFC 7693)
-   **`dcrypt_docs/algorithms/kdf/README.md`**: Key Derivation Functions.
    -   PBKDF2 (RFC 8018)
    -   HKDF (RFC 5869)
    -   Argon2 (Argon2d, Argon2i, Argon2id)
-   **`dcrypt_docs/algorithms/mac/README.md`**: Message Authentication Codes.
    -   HMAC (RFC 2104)
    -   Poly1305 (RFC 8439)
-   **`dcrypt_docs/algorithms/operation/README.md`**: Traits and builders for constructing cryptographic operations fluently (e.g., AEAD encryption/decryption, KDF derivation).
-   **`dcrypt_docs/algorithms/stream/README.md`**: Stream ciphers.
    -   ChaCha20 (RFC 8439)
-   **`dcrypt_docs/algorithms/types/README.md`**: Core data types with compile-time size guarantees and security properties (e.g., `Nonce`, `Salt`, `Tag`, `Digest`, `SymmetricKey`).
-   **`dcrypt_docs/algorithms/xof/README.md`**: Extendable Output Functions.
    -   SHAKE (XOF versions: `ShakeXof128`, `ShakeXof256` based on FIPS 202)
    -   BLAKE3 (XOF version)

## Core Traits and Types

Refer to `dcrypt_docs/algorithms/types/README.md` for detailed information on:

-   `Nonce<const N: usize>`: For cryptographic nonces.
-   `Salt<const N: usize>`: For cryptographic salts.
-   `Tag<const N: usize>`: For authentication tags.
-   `Digest<const N: usize>`: For hash function outputs.
-   `SymmetricKey<A: SymmetricAlgorithm, const N: usize>`: For symmetric keys.
-   And various compatibility marker traits (e.g., `ChaCha20Compatible`, `AesGcmCompatible`).

Key traits defining algorithm contracts are found in `dcrypt-api` but are heavily utilized here:

-   `api::HashAlgorithm`, `algorithms::hash::HashFunction`
-   `api::BlockCipher` (trait), `algorithms::block::BlockCipher` (trait within `algorithms`)
-   `api::SymmetricCipher`, `api::AuthenticatedCipher`
-   `algorithms::mac::Mac`
-   `algorithms::kdf::KeyDerivationFunction`
-   `algorithms::xof::ExtendableOutputFunction`

## Usage Example (Low-Level AES-128 Encryption)

This example demonstrates direct usage of an AES block cipher primitive. For most applications, using higher-level AEAD ciphers like AES-GCM (from `aead::Gcm`) is recommended.

```rust
use dcrypt_algorithms::block::aes::Aes128;
use dcrypt_algorithms::block::BlockCipher; // The trait from within algorithms
use dcrypt_algorithms::types::SymmetricKey;
use dcrypt_algorithms::types::algorithms::Aes128 as Aes128Algorithm; // Marker type
use dcrypt_algorithms::error::Result;
use rand::rngs::OsRng; // For key generation

fn aes128_block_encrypt_example() -> Result<()> {
    // Generate a random AES-128 key
    // Assuming SymmetricKey<Aes128Algorithm, 16> has a random generation method
    // or use:
    let mut key_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut key_bytes);
    let key = SymmetricKey::<Aes128Algorithm, 16>::new(key_bytes);

    let cipher = Aes128::new(&key); // Aes128::new expects &SecretBytes<16>
                                    // SymmetricKey<Aes128Algorithm, 16> derefs to [u8; 16]
                                    // and its SecretBuffer<16> also derefs to [u8;16]
                                    // This should align if SymmetricKey's inner `data` is a SecretBytes

    let mut block = [0x42u8; 16]; // A 16-byte block of data
    println!("Plaintext block: {:?}", block);

    cipher.encrypt_block(&mut block)?;
    println!("Encrypted block: {:?}", block);

    cipher.decrypt_block(&mut block)?;
    println!("Decrypted block: {:?}", block);

    assert_eq!(block, [0x42u8; 16]);
    Ok(())
}

// fn main() {
//     aes128_block_encrypt_example().expect("AES-128 example failed");
// }
```

## Security

The `algorithms` crate is foundational to the security of DCRYPT. Key security aspects include:

-   **Constant-Time Implementations**: As detailed in the project's policy, algorithms handling secret data (e.g., AES rounds, Poly1305 multiplication, HMAC processing) are designed to be constant-time.
-   **Zeroization**: `SecretBuffer` and other secure types from `dcrypt-common` are used for keys and sensitive intermediate values to ensure they are wiped from memory after use.
-   **Validation**: Input parameters (key lengths, nonce sizes, etc.) are validated to prevent misuse that could lead to security vulnerabilities. The `validate` module within `error` provides helpers for this.
-   **Minimal `unsafe` Code**: The crate strives to minimize or avoid `unsafe` blocks.

This crate provides the low-level building blocks. For application-level cryptography, it's generally recommended to use the higher-level abstractions in `dcrypt-symmetric`, `dcrypt-kem`, etc., which compose these primitives into secure schemes.