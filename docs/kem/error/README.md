# KEM Error Handling

This module defines the error handling infrastructure for the `dcrypt-kem` crate. It provides a detailed and structured `Error` type that captures failures during key encapsulation and decapsulation operations, integrating seamlessly with the broader `dcrypt` error handling system.

## Core Concepts

The error handling in this crate is designed around two main principles:

1.  **Contextual Detail:** Provide specific, informative errors about *what* went wrong during a KEM operation (e.g., a failure during `Encapsulation` vs. `Decapsulation`).
2.  **API Consistency:** Ensure that all errors can be converted into the top-level `dcrypt::api::error::Error` type, giving users a single, consistent error type to handle across the entire `dcrypt` library.

## The `Error` Enum

The central component is the `kem::error::Error` enum, which represents all possible failure modes within this crate.

```rust
pub enum Error {
    // A lower-level error from the `dcrypt-algorithms` crate.
    Primitive(PrimitiveError),

    // Errors specific to the KEM workflow stages.
    KeyGeneration { algorithm: &'static str, details: &'static str },
    Encapsulation { algorithm: &'static str, details: &'static str },
    Decapsulation { algorithm: &'static str, details: &'static str },

    // Errors for malformed or cryptographically invalid inputs.
    InvalidKey { key_type: &'static str, reason: &'static str },
    InvalidCiphertext { algorithm: &'static str, reason: &'static str },

    // Serialization or deserialization failures.
    Serialization { context: &'static str, details: &'static str },

    // I/O error (only when the `std` feature is enabled).
    #[cfg(feature = "std")]
    Io(std::io::Error),
}
```

This enum allows the crate to internally distinguish between different failure conditions, such as an invalid public key being used for encapsulation versus a malformed ciphertext during decapsulation.

### Error Conversion

A key feature of this module is its integration with the top-level API. The `kem::error::Error` type implements `From<Error> for dcrypt::api::error::Error`.

This means that any function within `dcrypt-kem` that returns a `Result<T, kem::error::Error>` can be transparently converted to a `Result<T, dcrypt::api::error::Error>` using the `?` operator. This provides a clean and uniform error-handling experience for the end-user, who typically only needs to interact with the high-level `dcrypt::api::error::Error`.

## Usage

When you call a function from the `dcrypt-kem` crate, the error you receive will already be converted to the `dcrypt::api::error::Error` type. You can then match on its variants to handle different kinds of failures.

```rust
use dcrypt::api::{self, Kem};
use dcrypt::kem::ecdh::EcdhP256;
use dcrypt::kem::ecdh::p256::EcdhP256Ciphertext; // Use the concrete type
use rand::rngs::OsRng;

fn main() {
    let mut rng = OsRng;
    let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();

    // Create a valid ciphertext, then tamper with it.
    let (mut ciphertext, _) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
    let mut ct_bytes = ciphertext.to_bytes();
    ct_bytes[5] ^= 0xFF; // Corrupt a byte
    
    // Attempting to use the tampered data will likely fail decapsulation.
    // Note: Creating a Ciphertext from raw bytes should also be handled with care.
    // Here we assume it's possible for demonstration, but a real implementation
    // might error here too. Let's create a new type instance for the example.
    let tampered_ciphertext = EcdhP256Ciphertext::from_bytes(&ct_bytes).unwrap();


    match EcdhP256::decapsulate(&sk, &tampered_ciphertext) {
        Ok(shared_secret) => {
            // This case is unlikely for a tampered ciphertext
            // but is possible if the tampered point is still valid.
            println!("Warning: Decapsulation succeeded, but secret is likely incorrect!");
        },
        Err(e) => {
            // The error `e` is a `dcrypt::api::error::Error`.
            // We can match on it to determine the cause.
            match e {
                api::error::Error::DecryptionFailed { context, message } => {
                    // This is a common error for tampered KEM ciphertexts where
                    // an authentication tag fails or the resulting point is invalid.
                    eprintln!("Decryption failed for '{}': {}", context, message);
                },
                api::error::Error::InvalidCiphertext { context, message } => {
                    // This error indicates the ciphertext was structurally invalid
                    // before decryption was even attempted.
                    eprintln!("Invalid ciphertext format for '{}': {}", context, message);
                },
                _ => {
                    eprintln!("An unexpected cryptographic error occurred: {:?}", e);
                }
            }
        }
    }
}
```

## Validation Utilities

The `error::validate` submodule provides a set of internal helper functions for checking preconditions within the KEM implementations. These functions are used to ensure that parameters (like key lengths or buffer sizes) are correct before proceeding with a cryptographic operation.

While these are not part of the public user-facing API, they are the source of the structured and consistent errors returned by the crate.