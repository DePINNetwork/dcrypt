# Poly1305 Message Authentication Code

## Overview

This module provides a constant-time, pure-Rust implementation of the **Poly1305** message authentication code, as specified in [RFC 8439](https://tools.ietf.org/html/rfc8439). Poly1305 is a high-speed polynomial evaluation MAC designed to ensure message integrity and authenticity.

The implementation is designed to be secure against side-channel attacks and integrates seamlessly with the `dcrypt` ecosystem's `Mac` trait, providing a consistent API with other authentication primitives.

## ⚠️ Security Warning: One-Time MAC

**Poly1305 is a one-time authenticator.** This is its most critical security property.

Using the same key to authenticate two different messages is catastrophic and will allow an attacker to forge authenticator tags for other messages. The security of the algorithm relies on the uniqueness of the key for each invocation.

For this reason, Poly1305 **should not be used as a general-purpose MAC**. It is almost always used as part of a higher-level AEAD (Authenticated Encryption with Associated Data) construction, such as **ChaCha20-Poly1305**. In such constructions, a stream cipher is used to generate a unique, single-use Poly1305 key for each message, thus satisfying the one-time-key requirement.

## Features

*   **RFC 8439 Compliant:** The implementation strictly follows the official standard, ensuring interoperability.
*   **Constant-Time Execution:** All cryptographic operations, including the polynomial evaluation and final reduction, are implemented using branch-free, constant-time arithmetic to mitigate timing side-channel attacks.
*   **Secure Memory Handling:** All key material (`r` and `s` components) is stored in a `SecretBuffer`, which securely zeroizes its contents upon being dropped.
*   **Standard API:** Implements the `dcrypt::algorithms::mac::Mac` trait, providing a consistent and ergonomic API with both one-shot and incremental (streaming) methods.

## Usage

### One-Shot Computation and Verification

The `Mac` trait provides convenient methods for simple, one-shot operations.

```rust
use dcrypt::algorithms::mac::{Poly1305, Mac, POLY1305_KEY_SIZE};

// A 32-byte key is required for Poly1305.
// IMPORTANT: This key must only be used ONCE for a single message.
let key = [0x42; POLY1305_KEY_SIZE];
let message = b"message to authenticate once";

// Compute the Poly1305 tag
let tag = Poly1305::compute_tag(&key, message).unwrap();
println!("Poly1305 Tag: {}", hex::encode(tag.as_ref()));

// Verify the tag
let is_valid = Poly1305::verify_tag(&key, message, &tag).unwrap();
assert!(is_valid);

// Verification with a tampered message will fail
let mut tampered_message = message.to_vec();
tampered_message ^= 1;
let is_invalid = Poly1305::verify_tag(&key, &tampered_message, &tag).unwrap();
assert!(!is_invalid);
```

### Incremental (Streaming) API

For messages that are not available all at once, you can use the incremental `update` and `finalize` methods.

```rust
use dcrypt::algorithms::mac::{Poly1305, Mac, POLY1305_KEY_SIZE};

let key = [0x85; POLY1305_KEY_SIZE]; // A different one-time key
let part1 = b"Cryptographic Forum ";
let part2 = b"Research Group";

// Create a new Poly1305 instance
let mut poly = Poly1305::new(&key).unwrap();

// Update with message parts
poly.update(part1).unwrap();
poly.update(part2).unwrap();

// Finalize to get the tag
let tag = poly.finalize().unwrap();

// Verification must use the same process
let full_message = [part1, part2].concat();
let is_valid = Poly1305::verify_tag(&key, &full_message, &tag).unwrap();
assert!(is_valid);
```

## Implementation Details

The implementation follows the specification in RFC 8439 closely.

*   **Polynomial Evaluation:** The core of the algorithm is the evaluation of a polynomial over the prime field defined by `p = 2^130 - 5`. Each 16-byte block of the message is interpreted as a little-endian integer and added to an accumulator.
*   **Key Structure:** The 32-byte key is split into two 16-byte components:
    *   `r`: The multiplier for the polynomial evaluation. It is "clamped" by clearing specific bits to ensure it remains within a secure range and to prevent certain cryptographic attacks.
    *   `s`: A one-time pad that is added to the result of the polynomial evaluation to produce the final tag.
*   **Finalization:** After processing all message blocks, the final accumulator value is added to `s` (mod 2^128) to produce the 16-byte authentication tag.

## Module Structure

*   `src/mac/poly1305/mod.rs`: Contains the public `Poly1305` struct, its implementation of the `Mac` trait, and the core cryptographic logic.
*   `src/mac/poly1305/tests.rs`: Contains unit and integration tests, including vectors from RFC 8439 to ensure correctness and compliance.
