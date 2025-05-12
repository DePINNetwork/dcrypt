# Falcon Digital Signature Algorithm (`sign/falcon`)

This module is intended to implement the Falcon digital signature algorithm. Falcon (Fast Fourier Lattice-based Compact Signatures Over NTRU) is a lattice-based signature scheme built upon the NTRU lattice structure and using a "hash-and-sign" paradigm with a trapdoor sampler (FastSampler). It was selected by NIST for standardization in the Post-Quantum Cryptography (PQC) project and is notable for its compact signature and public key sizes compared to many other PQC signature schemes.

**Note on Current Status:** The implementation in the provided codebase snapshot (`falcon/mod.rs`) is a placeholder. It defines the necessary structs for Falcon-512 and Falcon-1024 variants and implements the `api::Signature` trait with dummy logic. This documentation describes the intended functionality based on this structure and Falcon's specifications.

## Falcon Variants

The module outlines support for standard Falcon parameter sets:

1.  **`Falcon512`**:
    *   Targets NIST Security Level 1.
    *   Polynomial degree `N = 512`.
    *   Modulus `q = 12289`.
    *   Key/Signature Sizes (from `dcrypt-params`): PK=897B, SK=1281B, Sig=666B (approximate, can vary slightly).

2.  **`Falcon1024`**:
    *   Targets NIST Security Level 5.
    *   Polynomial degree `N = 1024`.
    *   Modulus `q = 12289`.
    *   Key/Signature Sizes (from `dcrypt-params`): PK=1793B, SK=2305B, Sig=1280B (approximate).

## Core Components and Types

-   **`FalconPublicKey(Vec<u8>)`**: Wrapper for Falcon public keys (typically a polynomial `h`). Implements `Zeroize`.
-   **`FalconSecretKey(Vec<u8>)`**: Wrapper for Falcon secret keys (typically consists of polynomials `f, g` and a trapdoor representation, often an NTRU basis `F, G`). Implements `Zeroize`.
-   **`FalconSignature(Vec<u8>)`**: Wrapper for Falcon signatures (contains a salt `r` and a polynomial vector `s`).

## `api::Signature` Trait Implementation

Each Falcon variant (`Falcon512`, `Falcon1024`) implements the `api::Signature` trait:

-   `name()`: Returns the specific variant name (e.g., "Falcon-512").
-   `keypair()`:
    *   **Placeholder Logic**: Fills byte vectors with random data for public and secret keys according to the sizes specified in `dcrypt-params` for that variant.
-   `public_key()`: Extracts the `FalconPublicKey` from the keypair.
-   `secret_key()`: Extracts the `FalconSecretKey` from the keypair.
-   `sign()`:
    *   **Placeholder Logic**: Returns a dummy signature `FalconSignature` filled with zeros, with a size appropriate for the variant.
-   `verify()`:
    *   **Placeholder Logic**: Always returns `Ok(())`, indicating successful verification.

## Security Basis

Falcon's security is based on the hardness of the Short Integer Solution (SIS) problem over NTRU lattices. Specifically, it relies on the difficulty of finding short vectors in these lattices, which is related to the NTRU problem.

## Intended Functionality (Once Fully Implemented)

Falcon operations involve arithmetic in polynomial rings `Z_q[x]/(x^N+1)`.

-   **Key Generation**:
    1.  Generate private polynomials `f, g` with small Gaussian integer coefficients.
    2.  Ensure `f, g` satisfy certain properties (e.g., `f*f_adj + g*g_adj = q`, where `_adj` is the adjoint).
    3.  The public key is `h = g * f^(-1) mod q`.
    4.  The secret key consists of `(f, g)` and potentially an LDL tree representation of the NTRU basis `[[f, g], [-g_adj, f_adj]]` which forms the trapdoor for efficient signing.
-   **Signing (Hash-and-Sign with FastSampler)**:
    1.  Hash the message `M` along with a random salt `r` to get a point `c` (a polynomial) in the target space: `c = Hash(r || M)`.
    2.  Use the secret key (specifically the trapdoor/NTRU basis) and the FastSampler algorithm to find a short polynomial vector `(s_1, s_2)` such that `s_1 + s_2*h = c mod q`.
    3.  The signature is `(r, s_2')` where `s_2'` is a compressed form of `s_2`. (Falcon has specific compression techniques for the signature).
-   **Verification**:
    1.  Recompute `c = Hash(r || M)` from the salt `r` in the signature and the message `M`.
    2.  Decompress `s_2'` to `s_2`.
    3.  Compute `s_1 = c - s_2*h mod q`.
    4.  Check if the norm of the vector `(s_1, s_2)` is below a certain bound (related to `sigma^2 * N`). If it is, the signature is valid.

The FastSampler algorithm is a key innovation in Falcon, allowing for efficient generation of signatures with the correct statistical distribution from the trapdoor. The use of an LDL tree representation of the NTRU basis is central to this.

The current placeholder structure correctly sets up the types and API adherence for a future, complete Falcon implementation.