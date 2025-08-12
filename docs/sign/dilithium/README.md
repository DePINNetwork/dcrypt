# Dilithium Digital Signature Scheme (`sign/dilithium`)

This document provides an overview of the `dilithium` module, a FIPS 204 compliant implementation of the Module-Lattice-based Digital Signature Algorithm (ML-DSA).

## Overview

The `dilithium` module offers a high-security, post-quantum signature scheme standardized by the National Institute of Standards and Technology (NIST). It is based on the hardness of the Module Learning With Errors (MLWE) and Module Short Integer Solution (MSIS) problems over polynomial rings, providing strong security guarantees against attacks from both classical and quantum computers.

This implementation provides the three security levels specified in the FIPS 204 standard:

*   **`Dilithium2`**: NIST Security Level 1 (≈ AES-128)
*   **`Dilithium3`**: NIST Security Level 3 (≈ AES-192)
*   **`Dilithium5`**: NIST Security Level 5 (≈ AES-256)

The signing process employs the Fiat-Shamir with Aborts paradigm, which uses rejection sampling to ensure that the generated signatures do not leak information about the secret key.

## Features

*   **FIPS 204 Compliant**: Strictly adheres to the final NIST FIPS 204 standard for ML-DSA. The implementation correctly follows the specified algorithms for arithmetic, sampling, and encoding, including the final `UseHint` rules.
*   **Deterministic Signing**: Signature generation is deterministic, meaning that for a given message and secret key, the output signature is always the same. This approach avoids reliance on a random number generator during signing, mitigating risks associated with weak or faulty RNGs.
*   **Comprehensive Test Suite**: The module is backed by an extensive test suite that covers:
    *   Basic sign and verify round-trips.
    *   Serialization and deserialization of keys and signatures.
    *   Correctness of core arithmetic functions against known values.
    *   Deep algebraic verification of the underlying mathematical relationships.
    *   Failure cases for tampered messages, signatures, or incorrect keys.
*   **Performance Benchmarks**: Includes a full benchmark suite to measure the performance of key generation, signing, and verification across all security levels and for various message sizes.

## Implementation Details

The implementation is modular, separating the core cryptographic logic into distinct components:

*   **`mod.rs`**: Defines the public API, including the `DilithiumPublicKey`, `DilithiumSecretKey`, and `DilithiumSignatureData` structs, and implements the `dcrypt-api::Signature` trait.
*   **`sign.rs`**: Contains the high-level logic for key generation, signing, and verification as specified in FIPS 204 Algorithms 9, 10, and 11.
*   **`arithmetic.rs`**: Implements the crucial mathematical functions required by Dilithium, such as `Power2Round`, `Decompose`, and the `MakeHint`/`UseHint` system for the hint mechanism.
*   **`encoding.rs`**: Handles the precise serialization and deserialization formats for keys and signatures, ensuring byte-for-byte compatibility with the standard.
*   **`sampling.rs`**: Implements the specified procedures for sampling polynomials from the Centered Binomial Distribution (`sample_poly_cbd_eta`) and the uniform distribution (`sample_polyvecl_uniform_gamma1`).
*   **`polyvec.rs`**: Defines polynomial vector structures (`PolyVecL`, `PolyVecK`) and their associated arithmetic operations, including matrix expansion from a seed.

### Security Invariants

The signing process rigorously enforces several critical invariants to ensure cryptographic security, as outlined in FIPS 204. This implementation validates these conditions during signature generation:

*   `||z||∞ ≤ γ1 - β`: The norm of the signature component `z` must be within this bound to prevent key recovery attacks.
*   `||LowBits(w - cs2)||∞ ≤ γ2 - β`: Ensures the uniformity of certain intermediate values.
*   `||ct0||∞ < γ2 - β`: A check on the norm of `c·t0` to ensure the hint mechanism is sound.
*   `hint_count ≤ ω`: The number of hints must not exceed the parameter `ω` to ensure the signature can be correctly verified.

If any of these checks fail, the signature attempt is aborted, and the process is restarted with a new nonce (`kappa`). This rejection sampling is essential to the security of the scheme.

## Usage

All Dilithium variants conform to the `dcrypt_api::Signature` trait, providing a consistent API.

```rust
use dcrypt::sign::dilithium::Dilithium3;
use dcrypt::api::Signature;
use rand::rngs::OsRng;

// 1. Generate a keypair for Dilithium Level 3
let (public_key, secret_key) = Dilithium3::keypair(&mut OsRng)
    .expect("Keypair generation failed");

// 2. Define a message to be signed
let message = b"This message is secured by post-quantum cryptography.";

// 3. Sign the message
let signature = Dilithium3::sign(message, &secret_key)
    .expect("Signing failed");

// 4. Verify the signature with the public key
let verification_result = Dilithium3::verify(message, &signature, &public_key);
assert!(verification_result.is_ok());
println!("Signature verified successfully!");

// 5. Attempting to verify with a different message will fail
let tampered_message = b"This is a different message.";
assert!(Dilithium3::verify(tampered_message, &signature, &public_key).is_err());
println!("Verification of tampered message failed as expected.");```

## Testing and Benchmarking

The module's correctness is validated by thousands of tests covering every aspect of the implementation.

To run the dedicated benchmark suite:

```bash
cargo bench --bench dilithium
```

This will produce a detailed performance report in the `target/criterion/` directory.

## References

*   [FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)