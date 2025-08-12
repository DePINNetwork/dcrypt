# Message Authentication Code (MAC)

## Overview

This module provides robust, constant-time implementations of Message Authentication Codes (MACs). MACs are used to verify the integrity and authenticity of a message. The implementations in this crate are designed with a focus on security, particularly resistance to side-channel attacks, and provide a type-safe, ergonomic API.

All MAC operations are built to be:
*   **Constant-Time:** Verification and core cryptographic operations are implemented to execute in constant time, preventing timing-based side-channel attacks.
*   **Secure by Default:** Sensitive key material is handled using secure memory buffers that are automatically zeroed when no longer in use.
*   **Ergonomic:** The API provides both simple one-shot methods and a flexible, chainable builder pattern for streaming operations.

## Provided Algorithms

This module implements the following MAC algorithms:

*   **HMAC (Hash-based Message Authentication Code):** An implementation of the HMAC standard as specified in RFC 2104. It is generic over the choice of hash function, allowing it to be used with any `HashFunction` provided in this crate (e.g., `Sha256`, `Sha512`).
*   **Poly1305:** A high-speed, one-time authenticator as specified in RFC 8439. It is crucial to note that Poly1305 is secure only when used with a unique key for every message. It is typically used as part of an AEAD construction like ChaCha20-Poly1305.

## Core Abstractions

The module is built around a set of traits that provide a consistent interface for all MAC algorithms.

### `trait Mac`

This is the central trait for all MAC implementations. It defines the core functionality for both one-shot and incremental processing.

```rust
pub trait Mac: Sized {
    type Key: AsRef<[u8]> + AsMut<[u8]> + Clone + Zeroize;
    type Tag: AsRef<[u8]> + AsMut<[u8]> + Clone;

    fn new(key: &[u8]) -> Result<Self>;
    fn update(&mut self, data: &[u8]) -> Result<&mut Self>;
    fn finalize(&mut self) -> Result<Self::Tag>;
    fn reset(&mut self) -> Result<()>;

    // Convenience methods
    fn compute_tag(key: &[u8], data: &[u8]) -> Result<Self::Tag>;
    fn verify_tag(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool>;
}
```

### `trait MacExt` and `MacBuilder`

For a more fluent API, the `MacExt` trait provides a `builder()` method that returns a `MacBuilder`. This is useful for constructing complex, multi-part messages.

```rust
// Example of the builder pattern
let tag = Hmac::<Sha256>::new(key)?
    .builder()
    .update(header)?
    .update(payload)?
    .finalize()?;
```

## Usage Examples

### HMAC-SHA256

HMAC is a general-purpose MAC that can be used with various hash functions.

#### One-Shot Computation and Verification

```rust
use dcrypt::algorithms::mac::{Hmac, Mac};
use dcrypt::algorithms::hash::Sha256;

let key = b"my-secret-key";
let message = b"this is the message to authenticate";

// Compute the HMAC tag
let tag = Hmac::<Sha256>::compute_tag(key, message).unwrap();
println!("HMAC-SHA256 Tag: {}", hex::encode(tag.as_ref()));

// Verify the tag
let is_valid = Hmac::<Sha256>::verify_tag(key, message, &tag).unwrap();
assert!(is_valid);

// Verification with a wrong key will fail
let is_invalid = Hmac::<Sha256>::verify_tag(b"wrong-key", message, &tag).unwrap();
assert!(!is_invalid);
```

#### Incremental (Streaming) API

```rust
use dcrypt::algorithms::mac::{Hmac, Mac, MacExt};
use dcrypt::algorithms::hash::Sha256;

let key = b"my-secret-key";
let header = b"header-part";
let body = b"body-part";

// Using the streaming API
let mut hmac = Hmac::<Sha256>::new(key).unwrap();
hmac.update(header).unwrap();
hmac.update(body).unwrap();
let tag1 = hmac.finalize().unwrap();

// Using the builder pattern
let mut hmac_builder = Hmac::<Sha256>::new(key).unwrap();
let tag2 = hmac_builder.builder()
    .update(header).unwrap()
    .update(body).unwrap()
    .finalize().unwrap();

assert_eq!(tag1, tag2);
```

### Poly1305

> **SECURITY WARNING:** Poly1305 is a **one-time** MAC. Using the same key to authenticate two different messages will compromise its security. It is typically used within higher-level protocols like AEAD ciphers (e.g., ChaCha20-Poly1305) that ensure key uniqueness for each message.

```rust
use dcrypt::algorithms::mac::{Poly1305, Mac, POLY1305_KEY_SIZE};

// A 32-byte key is required for Poly1305.
let key = [0x42; POLY1305_KEY_SIZE];
let message = b"message to authenticate once";

// Compute the Poly1305 tag
let tag = Poly1305::compute_tag(&key, message).unwrap();

// Verify the tag
let is_valid = Poly1305::verify_tag(&key, message, &tag).unwrap();
assert!(is_valid);
```

## Security Considerations

*   **Constant-Time Verification:** The `verify_tag` method for all MACs is implemented to be constant-time. This prevents attackers from learning information about the correct tag by measuring the time it takes for verification to fail.

*   **Secure Memory:** All secret key material is handled within a `SecretBuffer`, which ensures the memory is zeroed out when it's no longer needed, preventing key leakage from memory dumps.

*   **Poly1305 Key Uniqueness:** As mentioned above, the security of Poly1305 depends on using a key only once. Do not use `Poly1305` directly unless you have a mechanism to ensure key uniqueness for every message. For general-purpose authenticated messaging, prefer an AEAD cipher or HMAC.

## Module Structure

*   `src/mac/mod.rs`: Defines the core `Mac` trait and re-exports the implemented algorithms.
*   `src/mac/hmac/mod.rs`: Contains the generic HMAC implementation.
*   `src/mac/poly1305/mod.rs`: Contains the Poly1305 implementation.
