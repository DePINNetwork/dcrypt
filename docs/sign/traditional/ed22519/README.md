# Ed25519 Digital Signature Algorithm (`sign/traditional/ed25519`)

This module is intended to implement the Ed25519 digital signature algorithm. Ed25519 is an instance of the Edwards-curve Digital Signature Algorithm (EdDSA) using specific parameters for Curve25519. It is known for its high performance, relatively small key and signature sizes, and strong security properties, including resistance to many common side-channel attacks that can affect other elliptic curve schemes.

**Standard**: RFC 8032

**Note on Current Status:** The implementation in the provided codebase snapshot (`main.rs`) is a placeholder. It defines the necessary structs (`Ed25519PublicKey`, `Ed25519SecretKey`, `Ed25519Signature`) and implements the `api::Signature` trait with dummy logic. Constants are defined in `common.rs`. This documentation describes the intended functionality.

## Algorithm Overview

Ed25519 uses a Schnorr-like signature scheme on a twisted Edwards curve equivalent to Curve25519.

-   **Curve Parameters**: Uses a specific prime field, curve equation, and base point. Key constants like `ED25519_CURVE_ORDER` and `ED25519_BASE_Y` are defined in `dcrypt-params/src/traditional/ed25519.rs`.
-   **Key Generation**:
    1.  Generate a 32-byte secret seed `k`.
    2.  The private scalar `s` is derived by hashing `k` (first 32 bytes of SHA-512(k)), then clamping some bits.
    3.  The public key `A` is the point `s * B`, where `B` is the standard base point. `A` is encoded as a 32-byte string.
    4.  The Ed25519 "secret key" often refers to the original 32-byte seed `k`, or sometimes the concatenation of `k` and the encoding of `A`. The DCRYPT structure `Ed25519SecretKey` wraps `Vec<u8>`, implying it could hold the 32-byte seed.
-   **Signing**:
    1.  A 64-byte value `r_intermediate` is derived by hashing the second 32 bytes of SHA-512(k) concatenated with the message `M`.
    2.  Reduce `r_intermediate` modulo the curve order `L` to get scalar `r`.
    3.  Compute the point `R = r * B`.
    4.  Compute `S = (r + SHA512(encode(R) || encode(A) || M) * s) mod L`.
    5.  The signature is the concatenation of `encode(R)` (32 bytes) and `encode(S)` (32 bytes), totaling 64 bytes.
    *Note: Nonce generation (`r`) is deterministic, derived from the private key and message, which helps avoid issues with bad RNGs.*
-   **Verification**:
    1.  Parse the signature into `R_encoded` and `S_encoded`. Decode `R_encoded` to point `R` and `S_encoded` to scalar `S`. Check that `S` is less than `L`.
    2.  Decode public key `A_encoded` to point `A`.
    3.  Compute `h = SHA512(R_encoded || A_encoded || M)`.
    4.  Check the verification equation: `S * B == R + h * A`. If true, the signature is valid.

## Core Components and Types

-   **`Ed25519` Struct**: The main type representing the Ed25519 algorithm.
-   **`Ed25519PublicKey(Vec<u8>)`**: Wrapper for the 32-byte Ed25519 public key. Implements `Zeroize`.
-   **`Ed25519SecretKey(Vec<u8>)`**: Wrapper for the 32-byte Ed25519 secret key seed. Implements `Zeroize`.
-   **`Ed25519Signature(Vec<u8>)`**: Wrapper for the 64-byte Ed25519 signature.

Constants for key and signature sizes (`ED25519_PUBLIC_KEY_SIZE`, `ED25519_SECRET_KEY_SIZE`, `ED25519_SIGNATURE_SIZE`) are defined in `common.rs` (and sourced from `dcrypt-params`).

## `api::Signature` Trait Implementation

The `Ed25519` struct implements the `api::Signature` trait:

-   `name()`: Returns "Ed25519".
-   `keypair()`:
    *   **Placeholder Logic**: Fills 32-byte vectors with random data for the public and secret keys. A real implementation would perform the hash-and-clamp derivation for the private scalar and compute the public point.
-   `public_key()`: Extracts the `Ed25519PublicKey`.
-   `secret_key()`: Extracts the `Ed25519SecretKey`.
-   `sign()`:
    *   **Placeholder Logic**: Returns a dummy 64-byte signature filled with zeros.
-   `verify()`:
    *   **Placeholder Logic**: Always returns `Ok(())`.

## Security Features of Ed25519 (when fully implemented)

-   **No Per-Signature Randomness Requirement**: Deterministic nonce generation from secret key and message avoids vulnerabilities from weak RNGs.
-   **Collision Resilience**: Uses a hash of the message, so security relies on the hash function's collision resistance.
-   **Side-Channel Resistance**: The underlying Curve25519 operations and EdDSA structure are designed with side-channel resistance in mind (e.g., complete addition formulas).
-   **Fast Verification**: Verification is generally faster than signing.

This module provides the structural basis for a complete and secure Ed25519 implementation within DCRYPT.