# NTRU KEM (`kem/ntru`)

This module is intended to implement Key Encapsulation Mechanisms (KEMs) based on NTRU (Nth-degree Truncated polynomial Ring Units). NTRU is a lattice-based public-key cryptosystem. The snapshot includes placeholders for NTRU-HPS (NTRU Hope-Provably Secure) and NTRU-EES (NTRUEncrypt, an earlier NTRU scheme). NTRU variants were contenders in the NIST PQC standardization process.

**Note on Current Status:** The implementations in the provided codebase snapshot (`ntru/mod.rs`) are placeholders. They define the necessary structs (`NtruPublicKey`, `NtruSecretKey`, etc.) and implement the `api::Kem` trait with dummy logic. This documentation describes the intended functionality based on this structure and general NTRU principles.

## NTRU Variants (Placeholders)

1.  **`NtruHps` (NTRU Hope-Provably Secure)**:
    *   **Description**: A specific parameterization of NTRU, likely referring to submissions like NTRU-HPS to the NIST PQC competition. These aim for provable security under standard lattice assumptions.
    *   **Parameters**: Key parameters like `n` (polynomial degree), `q` (modulus), `p` (often 3 for private key elements), and `d` (number of non-zero coefficients in private keys) are defined in `dcrypt-params/src/pqc/ntru.rs` (e.g., `NTRU_HPS_2048_509`).
    *   **Key Sizes**: Vary by parameter set (e.g., NTRU-HPS-2048-509 public key is 699 bytes, secret key is 935 bytes).

2.  **`NtruEes` (NTRUEncrypt - an older variant often specified as EES)**:
    *   **Description**: An earlier version of NTRU, often specified in IEEE P1363.1. NTRU-HRSS (Hope-Relaxed-Simplified-Strong) is a more modern variant that also appeared in the NIST PQC process, often using similar parameter conventions.
    *   **Parameters**: Similar to NTRU-HPS, with specific values defined in `dcrypt-params` (e.g., `NTRU_HRSS_701`).
    *   **Key Sizes**: Also vary by parameter set (e.g., NTRU-HRSS-701 public key is 1138 bytes).

## Core Components and Types

-   **`NtruPublicKey(Vec<u8>)`**: Wrapper for NTRU public keys (typically a polynomial `h`). Implements `Zeroize`.
-   **`NtruSecretKey(Vec<u8>)`**: Wrapper for NTRU secret keys (typically comprises polynomials like `f`, `g`, or `f_p`). Implements `Zeroize`.
-   **`NtruSharedSecret(Vec<u8>)`**: Wrapper for the derived shared secret. Implements `Zeroize`.
-   **`NtruCiphertext(Vec<u8>)`**: Wrapper for NTRU ciphertexts (an encrypted message).

## `api::Kem` Trait Implementation

Both `NtruHps` and `NtruEes` structs implement the `api::Kem` trait:

-   `name()`: Returns "NTRU-HPS" or "NTRU-EES".
-   `keypair()`:
    *   **Placeholder Logic**: Fills byte vectors with random data for public and secret keys, using sizes appropriate for a default parameter set (e.g., NTRU-HPS-2048-509 for `NtruHps`).
-   `public_key()`: Extracts the `NtruPublicKey` from the keypair.
-   `secret_key()`: Extracts the `NtruSecretKey` from the keypair.
-   `encapsulate()`:
    *   **Placeholder Logic**: Generates random byte vectors for the ciphertext and a 32-byte shared secret.
-   `decapsulate()`:
    *   **Placeholder Logic**: Returns a dummy zero-filled 32-byte shared secret.

## Security Basis

NTRU's security is based on the hardness of the shortest vector problem (SVP) in a specific type of lattice derived from polynomial rings. It offers relatively small key sizes and fast operations compared to some other PQC schemes.

## Intended Functionality (Once Fully Implemented)

The core operations in NTRU involve arithmetic in a truncated polynomial ring `R = Z_q[x]/(x^N - 1)`.

-   **Key Generation**:
    1.  Generate private polynomials `f` and `g` with small coefficients (e.g., from `{-1, 0, 1}`). `f` must be invertible modulo `q` and modulo `p` (where `p` is often 3).
    2.  Compute `f_q = f^(-1) mod q`.
    3.  The public key is `h = p * f_q * g mod q` (or a variant depending on the specific NTRU scheme).
    4.  The secret key includes `f` and potentially `f_p = f^(-1) mod p` and `h`.
-   **Encapsulation (Simplified for KEM)**:
    1.  Generate a random ephemeral polynomial `r` with small coefficients.
    2.  The message to be encapsulated (which will form the shared secret, or be used to derive it) `m` is also represented as a polynomial, often with small coefficients.
    3.  Compute the ciphertext `e = r * h + m mod q`. (This is a simplified encryption; KEMs often use `m` as a seed for a KDF, and the ciphertext encrypts this seed).
    4.  The shared secret is derived from `m` (and possibly `r` or other values).
-   **Decapsulation**:
    1.  Compute `a = f * e mod q`.
    2.  Reduce coefficients of `a` modulo `p` to recover `m'` (this step uses the fact that `f * p * f_q * g * r + f * m = p * g * r + f * m`, and terms with `p` are "large" while `f*m` is "small").
    3.  Verify the recovered message/seed, possibly by re-encrypting with `r'` (recovered from `a` and `m'`) and comparing with `e`.
    4.  Derive the shared secret from the recovered `m'`.

Modern NTRU KEMs like NTRU-HPS include specific transformations (OWCPA - chosen plaintext to chosen ciphertext) to achieve IND-CCA2 security.

The placeholder structure provides a starting point for implementing these complex polynomial operations and KEM constructions.