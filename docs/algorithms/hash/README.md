# Hash Functions (`algorithms/hash`)

This module implements various cryptographic hash functions. Hash functions are fundamental cryptographic primitives that map input data of arbitrary size to a fixed-size string of bits (the hash digest). Secure hash functions exhibit properties like pre-image resistance, second pre-image resistance, and collision resistance.

The implementations in this module prioritize security, including attempts at constant-time behavior where relevant (though less critical for hashes than for ciphers/MACs involving secret keys) and secure handling of internal state.

## Implemented Hash Functions

1.  **SHA-1 (`sha1`)**
    *   **Standard**: FIPS 180-4
    *   **Output Size**: 160 bits (20 bytes)
    *   **Block Size**: 512 bits (64 bytes)
    *   **Security Notes**: SHA-1 is considered cryptographically broken and should **not** be used for new applications. It is provided primarily for compatibility with legacy systems.
    *   **Core Struct**: `algorithms::hash::sha1::Sha1`

2.  **SHA-2 Family (`sha2`)**
    *   **Standard**: FIPS 180-4
    *   **Variants**:
        *   `Sha224`: Output 224 bits (28 bytes), Block Size 512 bits (64 bytes)
        *   `Sha256`: Output 256 bits (32 bytes), Block Size 512 bits (64 bytes)
        *   `Sha384`: Output 384 bits (48 bytes), Block Size 1024 bits (128 bytes)
        *   `Sha512`: Output 512 bits (64 bytes), Block Size 1024 bits (128 bytes)
    *   **Security Notes**: Widely used and considered secure. Implementations include secure memory handling for intermediate states (e.g., using `EphemeralSecret` for message schedule words).
    *   **Core Structs**: `Sha224`, `Sha256`, `Sha384`, `Sha512`.

3.  **SHA-3 Family (`sha3`)**
    *   **Standard**: FIPS 202
    *   **Description**: Based on the Keccak sponge construction.
    *   **Variants**:
        *   `Sha3_224`: Output 224 bits (28 bytes), Rate 1152 bits (144 bytes)
        *   `Sha3_256`: Output 256 bits (32 bytes), Rate 1088 bits (136 bytes)
        *   `Sha3_384`: Output 384 bits (48 bytes), Rate 832 bits (104 bytes)
        *   `Sha3_512`: Output 512 bits (64 bytes), Rate 576 bits (72 bytes)
    *   **Security Notes**: A modern and secure hash function standard. Implementations focus on constant-time and side-channel hardened Keccak permutation.
    *   **Core Structs**: `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512`.

4.  **SHAKE (Fixed-Output Versions) (`shake`)**
    *   **Standard**: FIPS 202
    *   **Description**: While SHAKE functions are Extendable Output Functions (XOFs), this module provides fixed-output hash function interfaces for them, common in some applications. For true XOF behavior, see `algorithms::xof::shake`.
    *   **Variants**:
        *   `Shake128`: Fixed output of 256 bits (32 bytes). Underlying security strength of 128 bits.
        *   `Shake256`: Fixed output of 512 bits (64 bytes). Underlying security strength of 256 bits.
    *   **Core Structs**: `Shake128`, `Shake256`.

5.  **BLAKE2 Family (`blake2`)**
    *   **Standard**: RFC 7693
    *   **Description**: Optimized for speed on 64-bit platforms while maintaining high security.
    *   **Variants**:
        *   `Blake2b`: 64-bit optimized, digest up to 512 bits (64 bytes). Supports keyed hashing. Block Size 1024 bits (128 bytes).
        *   `Blake2s`: 32-bit optimized, digest up to 256 bits (32 bytes). Supports keyed hashing. Block Size 512 bits (64 bytes).
    *   **Security Notes**: Fast and secure. Implementations use `EphemeralSecret` for intermediate compression values.
    *   **Core Structs**: `Blake2b`, `Blake2s`.

## Key Traits and Types

-   **`HashFunction` Trait (`algorithms::hash::HashFunction`)**:
    *   Defines the common interface for hash functions.
    *   Associated types: `Algorithm` (marker for output/block sizes), `Output` (typically `Digest<N>`).
    *   Methods: `new`, `update`, `finalize`, `finalize_reset`, `digest` (one-shot).
    *   Static methods: `output_size`, `block_size`, `name`, `verify`.
-   **`HashAlgorithm` Trait (`algorithms::hash::HashAlgorithm`)**:
    *   A marker trait providing compile-time constants: `OUTPUT_SIZE`, `BLOCK_SIZE`, `ALGORITHM_ID`.
-   **`Digest<const N: usize>` (`algorithms::types::Digest`)**:
    *   A type-safe wrapper for hash digests, ensuring fixed size at compile time.
-   `common::security::SecretBuffer`, `common::security::EphemeralSecret`: Used for secure handling of internal state or temporary values in some hash implementations.

## Usage Example (SHA-256)

```rust
use dcrypt_algorithms::hash::{Sha256, HashFunction}; // HashFunction trait for .digest() etc.
use dcrypt_algorithms::error::Result;
use dcrypt_algorithms::types::Digest; // For the output type

fn sha256_example() -> Result<()> {
    let data = b"Hello, DCRYPT hash functions!";

    // One-shot hashing
    let digest1: Digest<32> = Sha256::digest(data)?;
    println!("SHA-256 Digest 1 (one-shot): {}", digest1.to_hex());

    // Incremental hashing
    let mut hasher = Sha256::new();
    hasher.update(b"Hello, ")?;
    hasher.update(b"DCRYPT ")?;
    hasher.update(b"hash functions!")?;
    let digest2: Digest<32> = hasher.finalize()?;
    println!("SHA-256 Digest 2 (incremental): {}", digest2.to_hex());

    assert_eq!(digest1, digest2);

    // Verification
    assert!(Sha256::verify(data, &digest1)?);
    println!("Verification successful!");

    Ok(())
}

// fn main() {
//     sha256_example().expect("SHA-256 example failed");
// }
```

## Security Notes

-   **Algorithm Choice**: Always choose hash functions appropriate for the required security level. Avoid deprecated algorithms like SHA-1 for new applications.
-   **Salt for Password Hashing**: When hashing passwords, always use a salt and a dedicated password-based key derivation function (PBKDF) like Argon2 or PBKDF2 (found in `algorithms::kdf`), not a raw hash function.
-   **Output Truncation**: While some applications truncate hash outputs, be aware that this can reduce the security properties of the hash function.