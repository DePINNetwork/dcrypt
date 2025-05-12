# Error Handling (`algorithms/error`)

This module defines the error handling mechanisms specific to the `algorithms` crate. It provides a custom `Error` enum and `Result` type, along with validation utilities.

## Core Components

1.  **`Error` Enum**:
    The primary error type for operations within the `algorithms` crate. It encompasses various error conditions:
    *   `Parameter { name: Cow<'static, str>, reason: Cow<'static, str> }`: For invalid input parameters.
    *   `Length { context: &'static str, expected: usize, actual: usize }`: For errors related to incorrect data lengths.
    *   `Authentication { algorithm: &'static str }`: For failures in authentication, such as AEAD tag verification.
    *   `NotImplemented { feature: &'static str }`: Indicates a feature or algorithm variant is not yet implemented.
    *   `Processing { operation: &'static str, details: &'static str }`: Generic error during a cryptographic operation.
    *   `MacError { algorithm: &'static str, details: &'static str }`: Specific error related to MAC computation or verification.
    *   `External { source: &'static str, details: String }` (std) / `External { source: &'static str }` (no_std): For wrapping errors from external sources or lower-level libraries.
    *   `Other(&'static str)`: A fallback for other miscellaneous errors.

    The `Error` enum implements `Debug`, `Clone`, `PartialEq`, `Eq`, and `Display`. When the `std` feature is enabled, it also implements `std::error::Error`.

2.  **`Result<T>` Type Alias**:
    A shorthand for `core::result::Result<T, Error>`, used as the return type for fallible operations within this crate.

3.  **Conversion to `api::Error`**:
    An `impl From<Error> for CoreError` (where `CoreError` is `api::error::Error`) is provided. This allows errors from the `algorithms` crate to be seamlessly converted into the core API error type, facilitating error handling in higher-level crates.

4.  **`validate` Module (`algorithms::error::validate`)**:
    This sub-module contains utility functions for common validation tasks, returning a `Result<()>`:
    *   `parameter(condition: bool, name: &'static str, reason: &'static str)`: Validates a general parameter condition.
    *   `length(context: &'static str, actual: usize, expected: usize)`: Validates an exact length.
    *   `min_length(context: &'static str, actual: usize, min: usize)`: Validates a minimum length.
    *   `max_length(context: &'static str, actual: usize, max: usize)`: Validates a maximum length.
    *   `authentication(is_valid: bool, algorithm: &'static str)`: Validates an authentication check.

## Error Philosophy

-   **Clarity**: Errors aim to be descriptive enough to help diagnose issues.
-   **Security**: Error messages avoid leaking sensitive information.
-   **Composability**: Errors can be converted to the `api::Error` type, allowing for unified error handling across the DCRYPT workspace.
-   **`no_std` Compatibility**: The error types and basic formatting work in `no_std` environments. More detailed string messages are often conditional on the `std` or `alloc` feature.

## Usage Example

```rust
use dcrypt_algorithms::error::{Error, Result, validate};

fn check_key_length(key: &[u8]) -> Result<()> {
    validate::length("Symmetric Key", key.len(), 32)?;
    // Or, for a more specific error:
    if key.len() < 16 {
        return Err(Error::Parameter {
            name: "key".into(), // Cow allows for owned strings if needed
            reason: "Key too short".into(),
        });
    }
    Ok(())
}

fn process_data(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        // Using a predefined error variant
        return Err(Error::Processing {
            operation: "Data Processing",
            details: "Input data cannot be empty",
        });
    }
    // ... actual processing ...
    Ok(data.to_vec()) // Placeholder
}

// Example of how an error might be handled
// fn main() {
//     let short_key = vec![0u8; 8];
//     match check_key_length(&short_key) {
//         Ok(_) => println!("Key length OK."),
//         Err(e) => println!("Key Error: {}", e),
//     }
//
//     match process_data(&[]) {
//         Ok(_) => println!("Processing OK."),
//         Err(e) => {
//             println!("Processing Error: {}", e);
//             // Convert to api::Error if needed for higher-level handling
//             let core_error: dcrypt_api::error::Error = e.into();
//             println!("Core Error: {}", core_error);
//         }
//     }
// }
```
This error module ensures that cryptographic operations within the `algorithms` crate can report failures in a structured and secure manner.