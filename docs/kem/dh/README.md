# Diffie-Hellman KEM (`kem/dh`)

This module is intended to implement Key Encapsulation Mechanisms (KEMs) based on the Diffie-Hellman (DH) key exchange protocol over finite fields (Modular Exponentiation groups, MODP).

**Note on Current Status:** The implementation in the provided codebase snapshot (`dh/mod.rs`) is a placeholder. It defines the necessary structs (`DhPublicKey`, `DhSecretKey`, etc.) and implements the `api::Kem` trait with dummy logic. This documentation describes the intended functionality based on the structure and common DH KEM practices.

## Algorithm Overview

The Diffie-Hellman key exchange allows two parties to establish a shared secret over an insecure channel. A KEM variant can be constructed from DH.

-   **Parameters**: A large prime `p` (modulus) and a generator `g`. These are public.
-   **Key Generation**:
    -   The recipient generates a private key `x` (a random exponent) and computes their public key `Y = g^x mod p`.
-   **Encapsulation (Sender)**:
    1.  Generates an ephemeral private key `k` (random exponent).
    2.  Computes an ephemeral public key `K_e = g^k mod p`. This `K_e` forms the KEM ciphertext.
    3.  Computes the shared secret `S = Y^k mod p = (g^x)^k mod p = g^(xk) mod p`.
    4.  The KEM might then derive a final shared secret from `S` using a KDF, e.g., `KDF(S)`.
-   **Decapsulation (Recipient)**:
    1.  Receives `K_e` (the KEM ciphertext).
    2.  Computes the shared secret `S = (K_e)^x mod p = (g^k)^x mod p = g^(kx) mod p`.
    3.  Derives the final shared secret using the same KDF, `KDF(S)`.

## Implemented Variant (Placeholder)

-   **`Dh2048`**:
    -   Intended to use a 2048-bit modulus, likely aligning with RFC 3526 Group 14 parameters.
    -   **Public Key (`DhPublicKey`)**: Represents `Y`. In the placeholder, it's a `Vec<u8>` of 256 bytes.
    -   **Secret Key (`DhSecretKey`)**: Represents `x`. In the placeholder, it's a `Vec<u8>` of 32 bytes (a common size for exponents in DH-2048).
    -   **Shared Secret (`DhSharedSecret`)**: Represents the derived shared secret. In the placeholder, it's a `Vec<u8>` of 32 bytes.
    -   **Ciphertext (`DhCiphertext`)**: Represents `K_e`. In the placeholder, it's a `Vec<u8>` of 256 bytes.

## `api::Kem` Trait Implementation

The `Dh2048` struct implements the `api::Kem` trait:

-   `name()`: Returns "DH-2048".
-   `keypair()`: Placeholder generates random byte vectors of appropriate (placeholder) sizes for public and secret keys.
-   `public_key()`: Extracts the public key component from the keypair.
-   `secret_key()`: Extracts the secret key component from the keypair.
-   `encapsulate()`: Placeholder returns dummy ciphertext and shared secret.
-   `decapsulate()`: Placeholder returns a dummy shared secret.

## Security Considerations (General for DH)

-   **Strong Parameters**: The prime `p` must be a safe prime, and the generator `g` must be chosen correctly to ensure a large subgroup, resisting attacks like the Pohlig-Hellman algorithm. Using standardized groups (like RFC 3526) is recommended.
-   **Ephemeral Keys**: For KEM-like behavior ensuring forward secrecy, the sender's key `k` should be ephemeral (generated fresh for each encapsulation).
-   **Key Derivation Function (KDF)**: The raw shared secret `g^(xk) mod p` should generally not be used directly as a cryptographic key. It should be passed through a KDF to derive one or more keys of appropriate length and randomness properties.
-   **Man-in-the-Middle (MitM) Attacks**: Basic DH is vulnerable to MitM attacks if public keys are not authenticated. KEMs typically assume the recipient's public key is authentic.

Once fully implemented, this module would provide a classical KEM based on the well-understood Diffie-Hellman problem.