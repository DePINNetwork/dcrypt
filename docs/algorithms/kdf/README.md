# Key Derivation Functions (`algorithms/kdf`)

This module implements various Key Derivation Functions (KDFs). KDFs are used to derive one or more secret keys from a master secret or password. They are essential for generating cryptographic keys with specific properties from various input materials.

The implementations focus on adhering to standards and providing secure, configurable options.

## Implemented KDFs

1.  **Argon2 (`argon2`)**
    *   **Description**: A modern, highly configurable password hashing function and KDF, winner of the Password Hashing Competition (PHC). It is designed to be resistant to GPU cracking attacks and time-memory trade-offs.
    *   **Variants**:
        *   `Argon2d`: Maximizes resistance to GPU cracking attacks (data-dependent memory access).
        *   `Argon2i`: Optimized to resist side-channel attacks (data-independent memory access).
        *   `Argon2id`: A hybrid version combining features of Argon2d and Argon2i, generally recommended for password hashing.
    *   **Parameters**: Memory cost (m), time cost (t, iterations), parallelism (p), salt, associated data (optional), output length.
    *   **Security Notes**: The recommended KDF for password hashing. Parameters must be chosen carefully to balance security and performance.
    *   **Core Struct**: `algorithms::kdf::argon2::Argon2<const S: usize>` (where `S` is salt size)
    *   **Parameter Struct**: `algorithms::kdf::argon2::Params<const S: usize>`

2.  **HKDF (HMAC-based Key Derivation Function) (`hkdf`)**
    *   **Standard**: RFC 5869
    *   **Description**: A two-step KDF:
        1.  **Extract**: Combines input keying material (IKM) and an optional salt into a fixed-length pseudorandom key (PRK) using HMAC.
        2.  **Expand**: Uses the PRK and optional context-specific information (info) to generate output keying material (OKM) of the desired length, again using HMAC.
    *   **Underlying Hash**: Can be used with any secure hash function (e.g., SHA-256, SHA-512). The implementation is generic over `H: HashFunction`.
    *   **Security Notes**: A strong and flexible KDF suitable for many applications. Requires a good source of IKM. Salt improves security, especially with weak IKM.
    *   **Core Struct**: `algorithms::kdf::hkdf::Hkdf<H: HashFunction, const S: usize>`
    *   **Parameter Struct**: `algorithms::kdf::hkdf::HkdfParams<const S: usize>`

3.  **PBKDF2 (Password-Based Key Derivation Function 2) (`pbkdf2`)**
    *   **Standard**: RFC 8018 (supersedes RFC 2898)
    *   **Description**: Applies a pseudorandom function (PRF), typically HMAC with a hash function, to an input password or passphrase along with a salt value, repeating the process many times (iterations).
    *   **Underlying PRF**: Typically HMAC-SHA1 (deprecated), HMAC-SHA256, or HMAC-SHA512. The implementation is generic over `H: HashFunction` for the HMAC.
    *   **Parameters**: Salt, iteration count, output key length.
    *   **Security Notes**: A widely used KDF for password hashing. The iteration count is crucial for security; it should be as high as tolerable for the application.
    *   **Core Struct**: `algorithms::kdf::pbkdf2::Pbkdf2<H: HashFunction, const S: usize>`
    *   **Parameter Struct**: `algorithms::kdf::pbkdf2::Pbkdf2Params<const S: usize>`

## Key Traits and Types

-   **`KeyDerivationFunction` Trait (`algorithms::kdf::KeyDerivationFunction`)**:
    *   Defines the common interface for KDFs.
    *   Associated types: `Algorithm` (marker), `Salt`.
    *   Methods: `new`, `derive_key`, `builder`, `generate_salt`.
    *   Static method: `security_level`.
-   **`PasswordHashFunction` Trait (`algorithms::kdf::PasswordHashFunction`)**:
    *   Extends `KeyDerivationFunction` specifically for password hashing.
    *   Methods: `hash_password`, `verify`, `benchmark`, `recommended_params`.
-   **`KdfAlgorithm` Trait (`algorithms::kdf::KdfAlgorithm`)**:
    *   Marker trait for KDF algorithms, defining constants like `MIN_SALT_SIZE`, `DEFAULT_OUTPUT_SIZE`, `ALGORITHM_ID`.
-   **`KdfOperation` Trait (`algorithms::kdf::KdfOperation`)**:
    *   Defines a builder pattern for KDF operations.
-   **`ParamProvider` Trait (`algorithms::kdf::ParamProvider`)**:
    *   For KDFs that have configurable parameters.
-   **`Salt<const S: usize>` (`algorithms::types::Salt`)**:
    *   Type-safe salt, with compatibility traits like `Pbkdf2Compatible`, `Argon2Compatible`, `HkdfCompatible`.
-   **`PasswordHash` Struct (`algorithms::kdf::PasswordHash`)**:
    *   A structure for storing password hashes in a common format (e.g., PHC string format).
-   **`SecurityLevel` Enum (`algorithms::kdf::SecurityLevel`)**:
    *   Represents the security strength of a KDF in bits.
-   `common::security::SecretVec`, `common::security::SecretBuffer`: Used for secure handling of passwords, IKM, and derived keys.

## Usage Example (PBKDF2-HMAC-SHA256)

```rust
use dcrypt_algorithms::kdf::pbkdf2::Pbkdf2;
use dcrypt_algorithms::hash::Sha256; // The hash function for HMAC
use dcrypt_algorithms::kdf::{KeyDerivationFunction, KdfOperation};
use dcrypt_algorithms::types::Salt;
use dcrypt_algorithms::error::Result;
use rand::rngs::OsRng; // For salt generation

fn pbkdf2_example() -> Result<()> {
    let password = b"mysecretpassword";
    let salt_bytes = Salt::<16>::random(&mut OsRng); // Generate a 16-byte salt
    let iterations = 100_000; // Recommended minimum can vary
    let output_key_length = 32; // e.g., for an AES-256 key

    // Create PBKDF2 instance with default parameters, then configure
    let mut kdf = Pbkdf2::<Sha256, 16>::new(); // Uses default salt size 16

    // Update parameters (optional, can also be set via builder)
    let mut params = kdf.params().clone(); // Assuming ParamProvider is implemented
    params.salt = salt_bytes.clone();
    params.iterations = iterations;
    params.key_length = output_key_length;
    kdf.set_params(params);

    // Derive key using the direct method
    let derived_key1 = kdf.derive_key(
        password,
        Some(salt_bytes.as_ref()), // Pass salt as &[u8]
        None,                      // PBKDF2 doesn't use 'info'
        output_key_length
    )?;
    println!("PBKDF2 Derived Key 1 (hex): {}", hex::encode(&derived_key1));

    // Derive key using the builder pattern
    let derived_key2 = kdf.builder()
        .with_ikm(password)
        .with_salt(salt_bytes.as_ref()) // Pass salt as &[u8]
        .with_output_length(output_key_length)
        // .with_iterations(iterations) // Assuming the builder would have this
        .derive()?;
    println!("PBKDF2 Derived Key 2 (hex): {}", hex::encode(&derived_key2));
    
    // Note: The builder example above assumes the builder can also set iterations.
    // The current KdfOperation trait doesn't have with_iterations.
    // For Pbkdf2, iterations are part of its internal params.

    assert_eq!(derived_key1, derived_key2);
    Ok(())
}

// fn main() {
//     pbkdf2_example().expect("PBKDF2 example failed");
// }
```

## Security Considerations

-   **Salt**: Always use a unique, cryptographically random salt for each password or IKM. Salts should be at least `MIN_SALT_SIZE` (typically 16 bytes).
-   **Iteration Count (for PBKDF2, Argon2)**: The number of iterations (or time/memory cost for Argon2) is critical for security against brute-force attacks. This should be set as high as performance allows for the target system. OWASP recommendations should be followed.
-   **Input Keying Material (IKM)**: For KDFs like HKDF, the quality of the IKM affects the strength of the derived keys. If the IKM has low entropy, the derived keys will also be weak.
-   **Output Length**: Derive keys of sufficient length for the target cryptographic algorithm (e.g., 32 bytes for AES-256).
-   **Associated Data/Info**: For KDFs that support it (like HKDF and Argon2), use distinct "info" or "associated data" parameters to bind derived keys to specific contexts or purposes, preventing cross-protocol attacks.