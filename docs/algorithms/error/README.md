# Error Handling in `dcrypt-algorithms`

This document provides an overview of the error handling philosophy and implementation within the `dcrypt-algorithms` crate. The error system is designed to be specific, informative, and compatible with both `std` and `no_std` environments, while seamlessly integrating with the broader `dcrypt` ecosystem's core error type.

## Philosophy

The primary goals of this error module are:

1.  **Specificity:** Provide detailed, actionable error variants that clearly indicate the nature of the failure (e.g., an invalid parameter vs. an authentication failure).
2.  **Security:** Ensure that error handling paths do not introduce side-channel vulnerabilities.
3.  **Ergonomics:** Offer convenient validation helpers to reduce boilerplate and improve code clarity throughout the crate.
4.  **Integration:** Define a clear conversion path from these specific algorithm errors to the more generic `dcrypt_api::Error` type used at the top level of the `dcrypt` library.

## Core Components

### The `Error` Enum

The central type is the `dcrypt_algorithms::error::Error` enum. It enumerates all possible failure modes for the cryptographic primitives in this crate.

| Variant | Fields | Purpose |
| :--- | :--- | :--- |
| `Parameter` | `name: Cow<'static, str>`, `reason: Cow<'static, str>` | Indicates that a function was called with an invalid parameter. For example, an unsupported key size or an invalid algorithm variant. |
| `Length` | `context: &'static str`, `expected: usize`, `actual: usize` | Signifies that a provided data slice (e.g., a key, nonce, or ciphertext) has an incorrect length. |
| `Authentication` | `algorithm: &'static str` | A critical error indicating that an authentication check has failed, such as an invalid AEAD tag or MAC. |
| `NotImplemented` | `feature: &'static str` | Used for algorithms or features that are planned but not yet implemented. |
| `Processing` | `operation: &'static str`, `details: &'static str` | A general-purpose error for failures that occur *during* a cryptographic computation, such as a message length overflow. |
| `MacError` | `algorithm: &'static str`, `details: &'static str` | A specific error for failures within Message Authentication Code (MAC) operations. |
| `External` | `source: &'static str`, `details: String` (std-only) | Wraps an error from an external dependency. The detailed message is only available when compiled with `std`. |
| `Other` | `&'static str` | A catch-all for miscellaneous errors that do not fit the other categories. |

### The `validate` Module

To simplify error checking and reduce boilerplate, the `error/validate.rs` file provides a set of helper functions. These functions perform a check and return a `Result<()>` directly, making them easy to use with the `?` operator.

**Before (Manual Error Handling):**

```rust
fn process_data(data: &[u8]) -> Result<()> {
    if data.len() < 32 {
        Err(Error::Length {
            context: "process_data input",
            expected: 32,
            actual: data.len(),
        })
    } else {
        // ... proceed
        Ok(())
    }
}
```

**After (Using the `validate` Module):**

```rust
use dcrypt::algorithms::validate;

fn process_data(data: &[u8]) -> Result<()> {
    validate::min_length("process_data input", data.len(), 32)?;
    // ... proceed
    Ok(())
}
```

The available validation functions include:
*   `validate::parameter(condition, name, reason)`
*   `validate::length(context, actual, expected)`
*   `validate::min_length(context, actual, min)`
*   `validate::max_length(context, actual, max)`
*   `validate::authentication(is_valid, algorithm)`

## Usage Patterns

### Generating Errors (Internal Crate Usage)

Functions within the `dcrypt-algorithms` crate should use the `validate` helpers to perform checks and propagate errors.

```rust
use dcrypt::algorithms::{validate, Result, Error};

fn set_key(key: &[u8]) -> Result<()> {
    validate::length("AES-256 Key", key.len(), 32)?;
    // ... logic to set the key
    Ok(())
}
```

### Handling Errors (External Crate Usage)

Users of the `dcrypt-algorithms` crate will receive a `dcrypt::algorithms::Result<T>`. They can handle these errors using a standard `match` statement.

```rust
use dcrypt::algorithms::hash::{Sha256, HashFunction};
use dcrypt::algorithms::Error;

fn main() {
    let result = Sha256::digest(b"some data");

    match result {
        Ok(digest) => {
            println!("Digest: {}", digest.to_hex());
        }
        Err(Error::Length { context, expected, actual }) => {
            eprintln!("Error: Invalid length for {} (expected {}, got {}).", context, expected, actual);
        }
        Err(e) => {
            eprintln!("An unexpected cryptographic error occurred: {}", e);
        }
    }
}
```

## Integration with the `dcrypt` Core Error System

The `dcrypt` ecosystem defines a top-level, more generic error type: `dcrypt_api::Error`. The `dcrypt_algorithms::Error` enum is designed to be more specific and detailed for internal use.

A crucial feature of this module is the implementation of `From<Error> for dcrypt_api::Error`. This allows for seamless and automatic conversion of a specific algorithm error into the generic core error. This is the primary mechanism by which errors from this crate "bubble up" to the top-level `dcrypt` API, providing a unified error handling experience for the end-user.

**Example of Conversion:**

A `dcrypt_algorithms::Error::Authentication { algorithm: "AES-GCM" }` will be automatically converted into a `dcrypt_api::Error::AuthenticationFailed { context: "AES-GCM", message: "authentication failed" }`.

## `no_std` Support

The error module is fully compatible with `no_std` environments when the `alloc` feature is enabled.

*   The `Parameter` variant uses `Cow<'static, str>` for its fields, allowing it to accept both static string slices (`&'static str`) and owned `String`s without requiring `std`.
*   The `External` error variant's `details` field is a `String` and is only available when the `std` feature is enabled. In a `no_std` build, it is omitted to avoid dependency on the standard library's string formatting and allocation.