# Classic McEliece KEM (`kem/mceliece`)

This module is intended to implement the Classic McEliece Key Encapsulation Mechanism. Classic McEliece is a code-based cryptographic scheme and was selected by NIST for standardization in the Post-Quantum Cryptography (PQC) project. It is known for its long history (dating back to 1978) and relatively large public key sizes but small ciphertexts.

**Note on Current Status:** The implementation in the provided codebase snapshot (`mceliece/mod.rs`) is a placeholder. It defines the necessary structs for different McEliece parameter sets (`McEliece348864`, `McEliece6960119`) and implements the `api::Kem` trait with dummy logic. This documentation describes the intended functionality based on this structure and McEliece's specifications.

## McEliece Variants

The module outlines support for standard McEliece parameter sets corresponding to different NIST security levels:

1.  **`McEliece348864`**:
    *   Corresponds to parameters often labeled `mceliece348864` or similar, aiming for NIST Security Level 1.
    *   Parameters (from `dcrypt-params`):
        *   `n` (code length): 3488
        *   `k` (code dimension): 2720
        *   `t` (error correction capability): 64
        *   Public Key Size: 261,120 bytes
        *   Secret Key Size: 6,492 bytes
        *   Ciphertext Size: 128 bytes
        *   Shared Secret Size: 32 bytes

2.  **`McEliece6960119`**:
    *   Corresponds to parameters often labeled `mceliece6960119` or similar, aiming for NIST Security Level 5.
    *   Parameters (from `dcrypt-params`):
        *   `n` (code length): 6960
        *   `k` (code dimension): 5413
        *   `t` (error correction capability): 119
        *   Public Key Size: 1,047,319 bytes
        *   Secret Key Size: 13,932 bytes
        *   Ciphertext Size: 240 bytes
        *   Shared Secret Size: 32 bytes

## Core Components and Types

-   **`McEliecePublicKey(Vec<u8>)`**: Wrapper for McEliece public keys (typically a large systematic generator matrix). Implements `Zeroize`.
-   **`McElieceSecretKey(Vec<u8>)`**: Wrapper for McEliece secret keys (includes the Goppa polynomial, support, and permutation matrix). Implements `Zeroize`.
-   **`McElieceSharedSecret(Vec<u8>)`**: Wrapper for the derived shared secret. Implements `Zeroize`.
-   **`McElieceCiphertext(Vec<u8>)`**: Wrapper for McEliece ciphertexts (an error vector added to a codeword).

## `api::Kem` Trait Implementation

Both `McEliece348864` and `McEliece6960119` structs implement the `api::Kem` trait:

-   `name()`: Returns the specific variant name (e.g., "McEliece-348864").
-   `keypair()`:
    *   **Placeholder Logic**: Fills byte vectors with random data for public and secret keys according to the sizes specified in `dcrypt-params`.
-   `public_key()`: Extracts the `McEliecePublicKey` from the keypair.
-   `secret_key()`: Extracts the `McElieceSecretKey` from the keypair.
-   `encapsulate()`:
    *   **Placeholder Logic**: Generates random byte vectors for the ciphertext and shared secret, matching the expected sizes for the variant.
-   `decapsulate()`:
    *   **Placeholder Logic**: Returns a dummy zero-filled shared secret of the correct size.

## Security Basis

Classic McEliece's security relies on the hardness of decoding a general linear code, which is an NP-hard problem. It also relies on the difficulty of distinguishing a permuted Goppa code (used in its construction) from a random linear code.

## Intended Functionality (Once Fully Implemented)

-   **Key Generation**:
    1.  Generate an irreducible Goppa polynomial `g(z)` of degree `t`.
    2.  Construct the support `L` (elements of `GF(2^m)` that are not roots of `g(z)`).
    3.  Form a parity-check matrix `H` for the Goppa code.
    4.  Transform `H` into a systematic generator matrix `G'` (e.g., `[I_k | Q]`).
    5.  Scramble `G'` using a random non-singular matrix `S` and a random permutation matrix `P` to get the public key `G_pub = S * G' * P`.
    6.  The secret key consists of `(S, g(z), P)` or equivalent information to decode.
-   **Encapsulation**:
    1.  Choose a random error vector `e` of weight `t`.
    2.  Generate a random message `m` (which will become part of the shared secret).
    3.  Compute the ciphertext `c = m * G_pub + e`.
    4.  The shared secret is derived from `m` and `e` (often `Hash(m || e)`).
-   **Decapsulation**:
    1.  Compute `c' = c * P^(-1)`.
    2.  Use the Goppa code decoding algorithm (e.g., Patterson's algorithm) with `g(z)` and `L` to decode `c'` and find the error vector `e'`. If `e'` has weight `t`, then `e' * P^(-1) = e`.
    3.  Recover `m'` by computing `(c' - e') * S^(-1)`. This `m'` will be `[m | 0]`.
    4.  Reconstruct the shared secret using the recovered `m` and `e`.
    5.  Implicitly, if decoding fails or the error weight is incorrect, decapsulation fails. Modern KEM variants often re-encrypt and compare to achieve CCA2 security.

The placeholder structure correctly identifies the key components and their expected sizes, laying the groundwork for a future full implementation.