# Dilithium Digital Signature Scheme (`sign/dilithium`)

This module is intended to implement the Dilithium digital signature algorithm. Dilithium is a lattice-based signature scheme built on the Fiat-Shamir with Aborts paradigm. It was selected by NIST for standardization as part of the Post-Quantum Cryptography (PQC) project due to its strong security properties and good performance characteristics.

**Note on Current Status:** The implementation in the provided codebase snapshot (`dilithium/mod.rs`) is a placeholder. It defines the necessary structs (`DilithiumPublicKey`, `DilithiumSecretKey`, `DilithiumSignature`) and implements the `api::Signature` trait with dummy logic for three common Dilithium variants. This documentation describes the intended functionality based on this structure and Dilithium's specifications.

## Dilithium Variants

The module outlines support for standard Dilithium parameter sets, corresponding to different NIST security levels:

1.  **`Dilithium2`**:
    *   Targets NIST Security Level 2 (comparable to AES-128 or SHA-256 collision resistance).
    *   Key parameters (e.g., matrix dimensions `k=4, l=4`, norm bound `eta=2`) are defined in `dcrypt-params/src/pqc/dilithium.rs` (`DILITHIUM2`).
    *   Key/Signature Sizes (from `dcrypt-params`): PK=1312B, SK=2528B, Sig=2420B.

2.  **`Dilithium3`**:
    *   Targets NIST Security Level 3 (comparable to AES-192 or SHA-384 collision resistance).
    *   Key parameters (e.g., `k=6, l=5`, `eta=4`) are defined in `dcrypt-params` (`DILITHIUM3`).
    *   Key/Signature Sizes: PK=1952B, SK=4000B, Sig=3293B.

3.  **`Dilithium5`**:
    *   Targets NIST Security Level 5 (comparable to AES-256 or SHA-512 collision resistance).
    *   Key parameters (e.g., `k=8, l=7`, `eta=2`) are defined in `dcrypt-params` (`DILITHIUM5`).
    *   Key/Signature Sizes: PK=2592B, SK=4864B, Sig=4595B.

All Dilithium variants use a polynomial degree `N=256` and modulus `Q=8380417`.

## Core Components and Types

-   **`DilithiumPublicKey(Vec<u8>)`**: Wrapper for Dilithium public keys (typically contains a seed `rho` for matrix `A` and a vector `t_1`). Implements `Zeroize`.
-   **`DilithiumSecretKey(Vec<u8>)`**: Wrapper for Dilithium secret keys (contains `rho`, `K`, `tr`, `s_1`, `s_2`, `t_0`). Implements `Zeroize`.
-   **`DilithiumSignature(Vec<u8>)`**: Wrapper for Dilithium signatures (contains a challenge `c_tilde`, a vector `z`, and hint vector `h`).

## `api::Signature` Trait Implementation

Each Dilithium variant (`Dilithium2`, `Dilithium3`, `Dilithium5`) implements the `api::Signature` trait:

-   `name()`: Returns the specific variant name (e.g., "Dilithium2").
-   `keypair()`:
    *   **Placeholder Logic**: Fills byte vectors with random data for public and secret keys according to the sizes specified in `dcrypt-params` for that variant.
-   `public_key()`: Extracts the `DilithiumPublicKey` from the keypair.
-   `secret_key()`: Extracts the `DilithiumSecretKey` from the keypair.
-   `sign()`:
    *   **Placeholder Logic**: Returns a dummy signature `DilithiumSignature` filled with zeros, with the size appropriate for the variant.
-   `verify()`:
    *   **Placeholder Logic**: Always returns `Ok(())`, indicating successful verification.

## Security Basis

Dilithium's security is based on the hardness of lattice problems over module lattices, specifically the Module Learning With Errors (MLWE) and Module Short Integer Solution (MSIS) problems. It is designed to be secure against attacks by quantum computers.

## Intended Functionality (Once Fully Implemented)

Dilithium operations involve arithmetic with polynomials over rings `Z_q[x]/(x^N+1)`.

-   **Key Generation**:
    1.  Expand seed `rho` to generate matrix `A`.
    2.  Sample secret polynomial vectors `s_1`, `s_2` with small coefficients (norm bound `eta`).
    3.  Compute `t = A * s_1 + s_2 mod q`.
    4.  The public key is `(rho, t_1)` where `t_1` is the high-order bits of `t`. The secret key contains `(rho, K, tr, s_1, s_2, t_0)` where `K` and `tr` are hash preimages and `t_0` is low-order bits of `t`.
-   **Signing (Fiat-Shamir with Aborts)**:
    1.  Generate a random masking vector `y` with small coefficients.
    2.  Compute `w = A * y mod q`. Let `w_1` be the high-order bits of `w`.
    3.  Generate a challenge polynomial `c` by hashing `(tr, message, w_1)`.
    4.  Compute `z = y + c * s_1 mod q`.
    5.  Compute `w - c * s_2 mod q`. If this or `z` have coefficients outside certain bounds (checked using `MakeHint` and `CheckNorm`), abort and restart signing (this happens with low probability).
    6.  The signature is `(c_tilde, z, h)` where `c_tilde` is a hash of `c` and `h` is a hint vector derived from `w - c*s_2`.
-   **Verification**:
    1.  Expand `rho` from the public key to get `A`.
    2.  Recompute `w'_1 = A*z - c*t_1 mod q` (using `c` recovered from `c_tilde`).
    3.  Verify that `z` has coefficients within bounds and that `h` is a valid hint for `w'_1 - c*t_0` (low-order part of `A*z - c*t`).
    4.  Verify that `c_tilde` matches the hash of the recomputed `c`.

The placeholder structure establishes the type definitions and API adherence for a future complete Dilithium implementation.