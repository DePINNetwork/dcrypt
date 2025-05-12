# KEM Error Handling (`kem/error`)

This module defines the error handling system specific to the Key Encapsulation Mechanism (KEM) operations within the `dcrypt-kem` crate. It provides a custom `Error` enum, a `Result` type alias, and validation helpers tailored for KEM functionalities.

## Core Components

1.  **`Error` Enum**:
    The primary error type for KEM operations. It includes variants for:
    *   `Primitive(PrimitiveError)`: Wraps errors originating from the lower-level `algorithms` crate (e.g., `algorithms::error::Error`).
    *   `KeyGeneration { algorithm: &'static str, details: &'static str }`: Errors during the key pair generation process.
    *   `Encapsulation { algorithm: &'static str, details: &'static str }`: Errors during the key encapsulation process.
    *   `Decapsulation { algorithm: &'static str, details: &'static str }`: Errors during the key decapsulation process. This often indicates an invalid ciphertext or an attempt to decapsulate with the wrong key.
    *   `InvalidKey { key_type: &'static str, reason: &'static str }`: Errors related to malformed or invalid cryptographic keys (public or secret).
    *   `InvalidCiphertext { algorithm: &'static str, reason: &'static str }`: Errors due to malformed or invalid KEM ciphertexts.
    *   `Serialization { context: &'static str, details: &'static str }`: Failures during serialization or deserialization of KEM-related objects.
    *   `Io(std::io::Error)` (std-only): Wraps standard I/O errors, converted to `String` in the `symmetric` crate error handling for `Clone` compatibility. The `kem/error/mod.rs` structure shows it would directly store `std::io::Error` if `Clone` wasn't a concern at this level, but the `Clone` impl shows stringification.

    The `Error` enum implements `Debug`, `Clone` (manually due to `std::io::Error`), and `Display`. If the `std` feature is enabled, it also implements `std::error::Error`.

2.  **`Result<T>` Type Alias**:
    A shorthand for `core::result::Result<T, kem::error::Error>`, used as the return type for fallible KEM operations.

3.  **Error Conversions**:
    *   `From<PrimitiveError> for Error`: Allows easy conversion of errors from the `algorithms` crate.
    *   `From<std::io::Error> for Error` (std-only): Allows conversion of I/O errors.
    *   `From<Error> for CoreError` (where `CoreError` is `api::error::Error`): Enables `kem::Error` to be converted into the DCRYPT API's core error type, facilitating consistent error handling in higher-level applications or hybrid schemes.

4.  **`validate` Module (`kem::error::validate`)**:
    This sub-module provides KEM-specific validation utility functions:
    *   `key_generation(...)`: For validating parameters or conditions during key generation.
    *   `encapsulation(...)`: For validating encapsulation inputs.
    *   `decapsulation(...)`: For validating decapsulation inputs.
    *   `key(...)`: For validating key formats or properties.
    *   `ciphertext(...)`: For validating KEM ciphertext formats.
    *   `serialization(...)`: For validating serialization/deserialization conditions.
    It also re-exports common validation functions (like `length`, `parameter`) from `api::error::validate`.

## Error Handling Philosophy

-   **Specificity**: Provides KEM-specific error variants for better diagnostics.
-   **Integration**: Smoothly integrates with the error systems of `algorithms` and `api` crates.
-   **Security**: Error messages are designed to be informative without leaking sensitive cryptographic material.

## Usage

KEM implementations within `dcrypt-kem` will use these error types and validation functions to report failures. For example:

```rust
// Hypothetical KEM operation
use dcrypt_kem::error::{self, Result, Error as KemError, validate as kem_validate};
// use dcrypt_algorithms::error::Error as AlgoError; // Example of an underlying error

fn generate_kem_keypair_internal() -> Result<([u8;32], [u8;32])> {
    // kem_validate::parameter(false, "RNG", "RNG not seeded")?; // Example validation
    kem_validate::key_generation(false, "MyKEM", "parameter validation failed")?;
    // This would cause Error::KeyGeneration
    unreachable!();
}

fn example_kem_error_handling() {
    match generate_kem_keypair_internal() {
        Ok((_pk, _sk)) => println!("Keypair generated"),
        Err(e) => {
            println!("KEM Error: {}", e);
            // Example of converting to api::Error
            let api_error: dcrypt_api::error::Error = e.into();
            println!("API Error: {}", api_error);

            // // Example: If it was an AlgoError originally
            // if let KemError::Primitive(AlgoError::Length {..}) = original_kem_error {
            //     println!("It was a length error from algorithms crate!");
            // }
        }
    }
}
```

This dedicated error module helps in creating robust and understandable KEM implementations.