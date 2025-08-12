# Hash-based Message Authentication Code (HMAC)

## Overview

This module provides a robust, secure, and constant-time implementation of the HMAC (Hash-based Message Authentication Code) algorithm, as specified in **RFC 2104** and **FIPS 198-1**.

HMAC is a mechanism for calculating a message authentication code involving a cryptographic hash function in combination with a secret key. It is used to simultaneously verify the data integrity and authenticity of a message.

This implementation is generic over the underlying hash function, allowing it to be used with any hash function that implements the `HashFunction` trait, such as `Sha256` or `Sha512`.

## Key Features

*   **Standards Compliant:** Fully compliant with RFC 2104 and FIPS 198-1.
*   **Generic over Hash Functions:** Can be instantiated with any compatible hash function (e.g., `Hmac<Sha256>`, `Hmac<Sha512>`).
*   **Constant-Time Implementation:** All cryptographic operations, especially key handling and tag verification, are implemented to be constant-time to mitigate timing-based side-channel attacks.
*   **Secure Memory Handling:** Secret key material (`ipad` and `opad`) is stored in a `SecretBuffer`, which is automatically zeroed when it goes out of scope to prevent accidental key leakage.
*   **Ergonomic API:** Provides both a simple one-shot `mac()` and `verify()` interface for straightforward use cases, and an incremental `update()`/`finalize()` API for streaming large messages.

## Security Design

The HMAC implementation in this crate was designed with a security-first approach:

1.  **Constant-Time Key Handling:** The processing of the input key is constant-time. As per the RFC, if the key is longer than the hash function's block size, it is hashed. If it's shorter, it is padded. The selection between the original key and the hashed key is performed using branchless, constant-time logic to avoid leaking information about the key's length.

2.  **Constant-Time Verification:** The `verify()` function is critical for security. This implementation avoids early-exit vulnerabilities by comparing the full length of the expected tag in all cases. The comparison itself uses `subtle::ConstantTimeEq` to prevent timing attacks that could otherwise leak information about the tag's value byte by byte.

3.  **Secure Zeroization:** The derived inner and outer padded keys (`ipad` and `opad`) are stored in `SecretBuffer`, a secure container that guarantees its contents are zeroed on drop. This prevents sensitive key material from lingering in memory.

4.  **Stateful Safety:** The HMAC object tracks its state. Once `finalize()` has been called, the object cannot be updated further. Any attempt to do so will result in an error, and the operation will be performed on a dummy state to ensure consistent timing, preventing state-misuse from creating a timing oracle.

## Usage Examples

### One-Shot Computation and Verification (Recommended)

For most use cases, the one-shot API is the simplest and safest way to use HMAC.

```rust
use dcrypt::algorithms::mac::{Hmac, Mac};
use dcrypt::algorithms::hash::Sha256;

let key = b"my-secret-key";
let message = b"this is the message to authenticate";

// 1. Compute the HMAC tag
let tag = Hmac::<Sha256>::mac(key, message).unwrap();
println!("HMAC-SHA256 Tag: {}", hex::encode(tag.as_ref()));

// 2. Verify the tag
let is_valid = Hmac::<Sha256>::verify(key, message, &tag).unwrap();
assert!(is_valid);

// 3. Verification with a wrong key will fail
let is_invalid_key = Hmac::<Sha256>::verify(b"wrong-key", message, &tag).unwrap();
assert!(!is_invalid_key);

// 4. Verification with a tampered message will fail
let is_invalid_msg = Hmac::<Sha256>::verify(key, b"tampered message", &tag).unwrap();
assert!(!is_invalid_msg);
```

### Incremental (Streaming) API

The streaming API is useful for processing large files or network streams without buffering the entire message in memory.

```rust
use dcrypt::algorithms::mac::{Hmac, Mac};
use dcrypt::algorithms::hash::Sha256;

let key = b"my-secret-key";
let header = b"header-part";
let body = b"body-part";

// Initialize the HMAC instance with the key
let mut hmac = Hmac::<Sha256>::new(key).unwrap();

// Update with different parts of the message
hmac.update(header).unwrap();
hmac.update(body).unwrap();

// Finalize to get the tag
let tag = hmac.finalize().unwrap();

// Verification can also be done incrementally
let mut verifier = Hmac::<Sha256>::new(key).unwrap();
verifier.update(header).unwrap();
verifier.update(body).unwrap();
let expected_tag = verifier.finalize().unwrap();

assert_eq!(tag.as_ref(), expected_tag.as_ref());
```

## API Reference

### `struct Hmac<H: HashFunction + Clone>`
The main struct for HMAC operations. It is generic over the hash function `H`.

*   **`Hmac::new(key: &[u8]) -> Result<Self>`**
    Constructs a new HMAC instance. The key is processed according to RFC 2104.

*   **`hmac.update(data: &[u8]) -> Result<()>`**
    Processes a chunk of input data. Can be called multiple times.

*   **`hmac.finalize() -> Result<Vec<u8>>`**
    Finalizes the computation and returns the authentication tag. The instance cannot be updated after this call.

*   **`Hmac::mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>>`**
    A convenient one-shot function to compute the HMAC tag for a given message.

*   **`Hmac::verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool>`**
    A convenient one-shot function to verify an HMAC tag in constant time.

## Module Location

The primary struct is available at `dcrypt::algorithms::mac::Hmac`.