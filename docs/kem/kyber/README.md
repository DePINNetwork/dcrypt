# Kyber KEM (`kem/kyber`)

This module is intended to implement the Kyber Key Encapsulation Mechanism. Kyber is a lattice-based cryptographic scheme chosen by the U.S. National Institute of Standards and Technology (NIST) for standardization as part of the Post-Quantum Cryptography (PQC) project. It is designed to be secure against attacks by both classical and quantum computers.

**Note on Current Status:** The implementation in the provided codebase snapshot (`kyber/*.rs`) is a placeholder. It defines the necessary structs and parameter sets for different Kyber variants (Kyber512, Kyber768, Kyber1024) and implements the `api::Kem` trait with dummy logic. This documentation describes the intended functionality based on this structure and Kyber's specifications. The actual cryptographic operations are not yet implemented in the snapshot.

## Kyber Variants

Kyber comes in several parameter sets, offering different security levels:

1.  **`Kyber512` (`kyber512.rs`)**:
    *   **NIST Security Level**: 1 (comparable to AES-128).
    *   **Parameter `k`**: 2.
    *   Key sizes, ciphertext size, and other parameters are defined in `dcrypt-params/src/pqc/kyber.rs` (`KYBER512_SIZES` and `KYBER512`).

2.  **`Kyber768` (`kyber768.rs`)**:
    *   **NIST Security Level**: 3 (comparable to AES-192).
    *   **Parameter `k`**: 3.
    *   Key sizes and other parameters are defined in `dcrypt-params` (`KYBER768_SIZES` and `KYBER768`).

3.  **`Kyber1024` (`kyber1024.rs`)**:
    *   **NIST Security Level**: 5 (comparable to AES-256).
    *   **Parameter `k`**: 4.
    *   Key sizes and other parameters are defined in `dcrypt-params` (`KYBER1024_SIZES` and `KYBER1024`).

## Core Components and Types (`common.rs`)

-   **`KyberBase<const K: usize>`**: A generic base struct intended to be parameterized by `K` (which corresponds to Kyber's `k` parameter: 2, 3, or 4). Type aliases like `Kyber512 = KyberBase<2>` are used.
-   **`KyberPublicKey(Vec<u8>)`**: Wrapper for Kyber public keys.
-   **`KyberSecretKey(Vec<u8>)`**: Wrapper for Kyber secret keys (implements `Zeroize`).
-   **`KyberSharedSecret(api::Key)`**: Wrapper for the derived shared secret (implements `Zeroize`).
-   **`KyberCiphertext(Vec<u8>)`**: Wrapper for Kyber ciphertexts.
-   **`KyberSizes` Struct**: Holds size parameters (public key, secret key, ciphertext, shared secret) for different Kyber variants. These are sourced from `dcrypt-params`.
-   **Validation Utilities**:
    *   `validate_kyber_parameters<K>()`: Checks if `K` is a valid Kyber parameter (2, 3, or 4).
    *   `get_sizes_for_k<K>()`: Returns the `KyberSizes` struct for a given `K`.

## `api::Kem` Trait Implementation

Each Kyber variant (`Kyber512`, `Kyber768`, `Kyber1024`) implements the `api::Kem` trait:

-   `name()`: Returns the specific variant name (e.g., "Kyber-768").
-   `keypair()`:
    *   Validates the Kyber parameter `K`.
    *   Retrieves size parameters using `get_sizes_for_k`.
    *   **Placeholder Logic**: Fills byte vectors with random data from the provided RNG for public and secret keys, according to the retrieved sizes.
    *   Includes a placeholder validation to check if generated keys are non-zero.
-   `public_key()`: Extracts the `KyberPublicKey` from the keypair.
-   `secret_key()`: Extracts the `KyberSecretKey` from the keypair.
-   `encapsulate()`:
    *   Retrieves size parameters.
    *   Validates the provided public key's length and performs placeholder content validation.
    *   **Placeholder Logic**: Fills byte vectors with random data for the ciphertext and shared secret.
-   `decapsulate()`:
    *   Retrieves size parameters.
    *   Validates the lengths of the provided secret key and ciphertext.
    *   Performs placeholder content validation on the secret key and ciphertext.
    *   **Placeholder Logic**: Returns a zero-filled shared secret of the correct size.

## Security Basis

Kyber's security is based on the hardness of solving the Learning With Errors (LWE) problem over module lattices. It is designed to be resistant to attacks from quantum computers.

## Intended Functionality (Once Fully Implemented)

-   **Key Generation**: Would involve generating polynomial vectors and matrices with small coefficients, and performing lattice-based computations to derive the public and secret key components.
-   **Encapsulation**: Would involve generating ephemeral secrets, performing polynomial arithmetic (multiplication, addition), adding error terms sampled from a specific distribution, and compressing the resulting ciphertext components.
-   **Decapsulation**: Would involve polynomial arithmetic using the secret key to remove the error terms from the ciphertext and recover the shared secret, followed by a re-encryption step for chosen-ciphertext (CCA2) security to verify the ciphertext's validity.

The current structure provides a clear skeleton for these future implementations, leveraging the DCRYPT API traits and parameter constants from `dcrypt-params`.