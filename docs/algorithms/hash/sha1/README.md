# SHA-1 Hash Function (`dcrypt::algorithms::hash::sha1`)

> ⚠️ **Security Warning: SHA-1 is Cryptographically Broken**
>
> The SHA-1 algorithm is considered cryptographically insecure and has been deprecated for most uses. It is vulnerable to practical collision attacks, which means it is possible for an attacker to create two different messages that produce the same hash.
>
> **Do not use SHA-1 for any security-sensitive applications**, such as digital signatures, password hashing, or certificate validation.
>
> This implementation is provided solely for interoperability with legacy systems that require it (e.g., verifying old Git commits or other non-security-critical checksums). For new applications, use a modern, secure hash function like **SHA-256**, **SHA-3**, or **BLAKE2**.

## Overview

This module provides a pure Rust implementation of the SHA-1 hash function as specified in **FIPS 180-4**. It is integrated into the `dcrypt` ecosystem and adheres to the standard `HashFunction` trait, offering a consistent API with other hash functions in the library.

## API and Features

-   **Standard Compliance:** The implementation follows the FIPS 180-4 standard and is validated against official NIST test vectors.
-   **Unified Interface:** Implements the `dcrypt::algorithms::hash::HashFunction` trait, providing a consistent API with other hash functions in the crate.
-   **Type-Safe Digests:** Produces a `Digest<20>`, ensuring a compile-time guarantee of a 20-byte (160-bit) output.
-   **One-Shot and Incremental Hashing:** Supports both a simple `digest()` method for single inputs and an incremental `update()`/`finalize()` API for streaming data.

## Usage Examples

### One-Shot Hashing

The `digest()` method is the simplest way to compute a hash for a single piece of data.

```rust
use dcrypt::algorithms::hash::{Sha1, HashFunction};

let data = b"hello world";
let digest = Sha1::digest(data).unwrap();

// The digest can be easily converted to a hex string for display.
let hex_digest = digest.to_hex();

println!("Input: \"{}\"", String::from_utf8_lossy(data));
println!("SHA-1 Digest: {}", hex_digest);

assert_eq!(hex_digest, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
```

### Incremental (Streaming) Hashing

For larger inputs, such as files or network streams, the incremental API can be used to process data in chunks.

```rust
use dcrypt::algorithms::hash::{Sha1, HashFunction};

// Create a new hasher instance
let mut hasher = Sha1::new();

// Feed data in multiple parts
hasher.update(b"this is the first part of the message, ")
      .unwrap()
      .update(b"and this is the second part.")
      .unwrap();

// Finalize the hash computation
let digest = hasher.finalize().unwrap();

// Verify the result against the one-shot hash of the combined message
let combined_data = b"this is the first part of the message, and this is the second part.";
let expected_digest = Sha1::digest(combined_data).unwrap();

assert_eq!(digest, expected_digest);
println!("Incremental Digest: {}", digest.to_hex());
```

## Final Security Reminder

Again, it is crucial to understand that SHA-1 does not provide adequate security for modern applications. Always prefer stronger algorithms like `Sha256` or `Sha3_256` unless you have a specific and well-justified need for legacy compatibility.