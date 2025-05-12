# Rainbow Digital Signature Algorithm (`sign/rainbow`)

This module is intended to implement the Rainbow Digital Signature Algorithm. Rainbow is a multivariate public key cryptosystem (MPKC) based on the difficulty of solving systems of multivariate quadratic equations over a finite field. It was one of the signature schemes selected by NIST for standardization in the Post-Quantum Cryptography (PQC) project, particularly for applications requiring short signatures where public key size is less of a concern.

**Note on Current Status:** The implementation in the provided codebase snapshot (`rainbow/mod.rs`) is a placeholder. It defines the necessary structs for different Rainbow variants (Rainbow-I, Rainbow-III, Rainbow-V) and implements the `api::Signature` trait with dummy logic. This documentation describes the intended functionality based on this structure and Rainbow's specifications.

## Rainbow Variants

Rainbow is parameterized by the number of variables, the structure of its "oil" and "vinegar" variables across layers, and the finite field size. The module outlines support for standard Rainbow parameter sets corresponding to different NIST security levels:

1.  **`RainbowI`**:
    *   Targets NIST Security Level 1.
    *   Parameters (e.g., `v1=36, o1=32, o2=32` over `GF(16)`) are defined in `dcrypt-params/src/pqc/rainbow.rs` (`RAINBOW_I`).
    *   Key/Signature Sizes (from `dcrypt-params`): PK=161.6KB, SK=103.6KB, Sig=64B.

2.  **`RainbowIII`**:
    *   Targets NIST Security Level 3.
    *   Parameters (e.g., `v1=56, o1=48, o2=44` over `GF(256)`) are defined in `dcrypt-params` (`RAINBOW_III`).
    *   Key/Signature Sizes: PK=861.4KB, SK=611.3KB, Sig=96B.

3.  **`RainbowV`**:
    *   Targets NIST Security Level 5.
    *   Parameters (e.g., `v1=84, o1=64, o2=48` over `GF(256)`) are defined in `dcrypt-params` (`RAINBOW_V`).
    *   Key/Signature Sizes: PK=1885.4KB, SK=1375.7KB, Sig=128B.

*(Note: The parameters `v`, `o`, `l` in `dcrypt-params` map to the vinegar and oil variables, and layer structure of Rainbow's central map.)*

## Core Components and Types

-   **`RainbowPublicKey(Vec<u8>)`**: Wrapper for Rainbow public keys (a set of multivariate quadratic polynomials). Implements `Zeroize`.
-   **`RainbowSecretKey(Vec<u8>)`**: Wrapper for Rainbow secret keys (contains affine maps `S`, `T` and the coefficients of the easily invertible central map `F`). Implements `Zeroize`.
-   **`RainbowSignature(Vec<u8>)`**: Wrapper for Rainbow signatures (a preimage vector `x`).

## `api::Signature` Trait Implementation

Each Rainbow variant (`RainbowI`, `RainbowIII`, `RainbowV`) implements the `api::Signature` trait:

-   `name()`: Returns the specific variant name (e.g., "Rainbow-I").
-   `keypair()`:
    *   **Placeholder Logic**: Fills byte vectors with random data for public and secret keys according to the sizes specified in `dcrypt-params` for that variant.
-   `public_key()`: Extracts the `RainbowPublicKey` from the keypair.
-   `secret_key()`: Extracts the `RainbowSecretKey` from the keypair.
-   `sign()`:
    *   **Placeholder Logic**: Returns a dummy signature `RainbowSignature` filled with zeros, with a size appropriate for the variant.
-   `verify()`:
    *   **Placeholder Logic**: Always returns `Ok(())`, indicating successful verification.

## Security Basis

Rainbow's security relies on the MQ-problem: the assumed difficulty of solving a system of `m` random multivariate quadratic equations in `n` variables over a finite field. The secret key provides a trapdoor (the structure `P = S o F o T`) that allows efficient inversion of the public map for a given hash digest.

## Intended Functionality (Once Fully Implemented)

Rainbow is an Oil and Vinegar signature scheme with multiple layers.

-   **Key Generation**:
    1.  Choose two invertible affine maps, `S` and `T`, over `GF(q)`.
    2.  Construct a central map `F` which is a set of quadratic polynomials designed to be easily invertible given some "oil" variables. `F` typically has multiple layers.
    3.  The secret key is `(S, F, T)`.
    4.  The public key `P` is the composition `P = S o F o T`. The polynomials of `P` appear random.
-   **Signing**:
    1.  To sign a message `M`, first hash it to a digest `y = Hash(M)`.
    2.  Find a preimage `x` such that `P(x) = y`. This is done by:
        a.  Compute `y' = S^(-1)(y)`.
        b.  Invert `F`: find `x'` such that `F(x') = y'`. This is efficient because `F` has a special (oil and vinegar) structure. It involves guessing oil variables and solving a linear system for vinegar variables. Repeat if no solution.
        c.  Compute `x = T^(-1)(x')`. This `x` is the signature.
-   **Verification**:
    1.  Given a message `M`, signature `x`, and public key `P`.
    2.  Compute `y = Hash(M)`.
    3.  Compute `y_test = P(x)`.
    4.  The signature is valid if `y_test == y`.

Rainbow's layered structure helps to resist certain attacks against simpler Oil and Vinegar schemes. The current placeholders establish the API for a future full implementation of these multivariate operations.