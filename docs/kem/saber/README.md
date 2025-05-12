# SABER KEM (`kem/saber`)

This module is intended to implement the SABER Key Encapsulation Mechanism. SABER is a lattice-based cryptographic scheme based on the Module Learning With Rounding (MLWR) problem. It was a finalist in the NIST Post-Quantum Cryptography (PQC) standardization process. SABER is known for its efficiency and relatively balanced performance characteristics.

**Note on Current Status:** The implementation in the provided codebase snapshot (`saber/mod.rs`) is a placeholder. It defines the necessary structs for different SABER variants (LightSaber, Saber, FireSaber) and implements the `api::Kem` trait with dummy logic. This documentation describes the intended functionality based on this structure and SABER's specifications.

## SABER Variants

SABER comes in several parameter sets, targeting different NIST security levels:

1.  **`LightSaber`**:
    *   Targets NIST Security Level 1 (comparable to AES-128).
    *   Parameters (e.g., polynomial degree `N`, modulus `Q`, dimension `L`, compression bits `EP`, `ET`) are defined in `dcrypt-params/src/pqc/saber.rs` (`LIGHTSABER`).
    *   Key Sizes (from `dcrypt-params`): PK=672B, SK=1568B, CT=736B, SS=32B.

2.  **`Saber`**:
    *   Targets NIST Security Level 3 (comparable to AES-192).
    *   Parameters are defined in `dcrypt-params` (`SABER`).
    *   Key Sizes: PK=992B, SK=2304B, CT=1088B, SS=32B.

3.  **`FireSaber`**:
    *   Targets NIST Security Level 5 (comparable to AES-256).
    *   Parameters are defined in `dcrypt-params` (`FIRESABER`).
    *   Key Sizes: PK=1312B, SK=3040B, CT=1472B, SS=32B.

## Core Components and Types

-   **`SaberPublicKey(Vec<u8>)`**: Wrapper for SABER public keys (typically a seed for matrix `A` and a vector `b`). Implements `Zeroize`.
-   **`SaberSecretKey(Vec<u8>)`**: Wrapper for SABER secret keys (typically a secret vector `s`). Implements `Zeroize`.
-   **`SaberSharedSecret(Vec<u8>)`**: Wrapper for the derived 32-byte shared secret. Implements `Zeroize`.
-   **`SaberCiphertext(Vec<u8>)`**: Wrapper for SABER ciphertexts (contains a vector `b'` and a rounded polynomial `c_m`).

## `api::Kem` Trait Implementation

Each SABER variant (`LightSaber`, `Saber`, `FireSaber`) implements the `api::Kem` trait:

-   `name()`: Returns the specific variant name (e.g., "LightSaber").
-   `keypair()`:
    *   **Placeholder Logic**: Fills byte vectors with random data for public and secret keys according to the sizes specified in `dcrypt-params` for that variant.
-   `public_key()`: Extracts the `SaberPublicKey` from the keypair.
-   `secret_key()`: Extracts the `SaberSecretKey` from the keypair.
-   `encapsulate()`:
    *   **Placeholder Logic**: Generates random byte vectors for the ciphertext (size specific to variant) and a 32-byte shared secret.
-   `decapsulate()`:
    *   **Placeholder Logic**: Returns a dummy zero-filled 32-byte shared secret.

## Security Basis

SABER's security is based on the hardness of the Module Learning With Rounding (MLWR) problem, which is related to the Learning With Errors (LWE) problem. It aims for security against both classical and quantum attackers.

## Intended Functionality (Once Fully Implemented)

SABER operations involve arithmetic with polynomials over rings `Z_q[x]/(x^N+1)` and `Z_p[x]/(x^N+1)`.

-   **Key Generation**:
    1.  Generate a secret vector `s` with small coefficients.
    2.  Generate a public matrix `A` (often derived from a seed).
    3.  Compute `b = A*s + h1 mod q` (where `h1` is a fixed public polynomial, and computations involve rounding).
    4.  The public key is `(seed_A, b)`. The secret key is `s` (and potentially other values for decapsulation or FO transform).
-   **Encapsulation**:
    1.  Generate an ephemeral secret `s'` and error terms `e'`, `e''`.
    2.  Generate a random message `m` (e.g., 32 bytes).
    3.  Compute `b' = A^T * s' + h2 mod q` (rounding involved).
    4.  Compute `v = b^T * s' mod q`.
    5.  Compute `c_m = v + m * (q/2) mod p` (simplified, involves rounding and encoding `m`).
    6.  The ciphertext is `(b', c_m)`.
    7.  The shared secret is derived using a KDF from `m` and potentially other values like the public key and ciphertext (e.g., `K = H(m, pk, ct)`).
-   **Decapsulation**:
    1.  Receive `(b', c_m)`.
    2.  Compute `v' = b'^T * s mod q` (rounding involved).
    3.  Recover message `m'` from `c_m` and `v'` by removing the rounding and the `s^T A^T s'` term. `m' = (c_m - v') * (2/p) mod 2` (simplified).
    4.  To achieve CCA2 security, SABER typically re-encrypts the recovered `m'` using newly generated randomness and compares the re-encrypted ciphertext with the received one. If they match, the shared secret `K = H(m', pk, ct)` is output; otherwise, a random key is output.

The placeholder structure sets the stage for these polynomial-based operations and the KEM construction.