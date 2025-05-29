# Elliptic Curve Diffie-Hellman KEM (`kem/ecdh`)

This module implements Key Encapsulation Mechanisms (KEMs) based on the Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol. ECDH adapts the Diffie-Hellman concept to groups of points on an elliptic curve, offering smaller key sizes for equivalent security compared to traditional DH over finite fields.

The implementations aim for security against timing attacks and adhere to best practices for key derivation, drawing inspiration from standards like RFC 9180 (HPKE) for the use of Key Derivation Functions (KDFs).

## Algorithm Overview

ECDH key exchange allows two parties to establish a shared secret. A KEM variant can be constructed from ECDH:

-   **Parameters**: A specific elliptic curve (e.g., NIST P-256, P-384, P-521) and a base point `G` on that curve. These are public.
-   **Key Generation (Recipient)**:
    1.  Generates a private key `d_R` (a random scalar).
    2.  Computes their public key `Q_R = d_R * G` (elliptic curve point multiplication).
-   **Encapsulation (Sender)**:
    1.  Generates an ephemeral private key `d_S` (a random scalar).
    2.  Computes an ephemeral public key `Q_S = d_S * G`. This `Q_S` (typically serialized in compressed format) forms the KEM ciphertext.
    3.  Computes the shared secret point `P = d_S * Q_R = d_S * (d_R * G) = (d_S * d_R) * G`.
    4.  The actual shared secret key `K` is derived from the x-coordinate of `P` (and potentially other information like `Q_S` and `Q_R` for binding) using a KDF: `K = KDF(x_P, Q_S_bytes, Q_R_bytes, context_string)`.
-   **Decapsulation (Recipient)**:
    1.  Receives `Q_S` (the KEM ciphertext).
    2.  Computes the shared secret point `P = d_R * Q_S = d_R * (d_S * G) = (d_R * d_S) * G`.
    3.  Derives the shared secret key `K` using the same KDF, incorporating `x_P`, `Q_S_bytes`, their own public key `Q_R_bytes`, and the context string.

## Implemented Variants

1.  **`EcdhP256` (`p256`)**:
    *   Uses the NIST P-256 (secp256r1) curve.
    *   **Shared Secret Derivation**: Uses HKDF with SHA-256.
    *   **Public Key / Ciphertext Format**: Compressed EC points (33 bytes for P-256).
    *   Refer to `docs/kem/ecdh/p256/README.md`.

2.  **`EcdhP384` (`p384`)**:
    *   Uses the NIST P-384 (secp384r1) curve.
    *   **Shared Secret Derivation**: Uses HKDF with SHA-384.
    *   **Public Key / Ciphertext Format**: Compressed EC points (49 bytes for P-384).
    *   Refer to `docs/kem/ecdh/p384/README.md`.

3.  **`EcdhP521` (`p521`)**:
    *   Uses the NIST P-521 (secp521r1) curve.
    *   **Shared Secret Derivation**: Uses HKDF with SHA-512.
    *   **Public Key / Ciphertext Format**: Compressed EC points (67 bytes for P-521).
    *   Refer to `docs/kem/ecdh/p521/README.md`.

## KDF Usage and Domain Separation
The ECDH-KEM implementations use HKDF as the Key Derivation Function.
-   The **Input Keying Material (IKM)** for HKDF is the x-coordinate of the raw ECDH shared secret point.
-   The **Salt** for HKDF is the byte representation of the ephemeral public key generated during encapsulation (in compressed format).
-   An **Info** string, typically including the KEM name and a version (e.g., `"ECDH-P256-KEM v2.0.0"`), is used for domain separation. The version string `v2.0.0` (defined as `KEM_KDF_VERSION` in `kem::ecdh::mod.rs`) signifies the use of compressed points for keys and ciphertexts, and specific KDF inputs.

## `api::Kem` Trait Implementation

All `EcdhP*` structs implement the `api::Kem` trait, providing a consistent interface for key generation, encapsulation, and decapsulation.

## Security Considerations

-   **Curve Choice**: Standard, well-vetted elliptic curves (NIST P-curves) are used.
-   **Point Validation**: Public keys received from external parties and ephemeral keys generated internally are validated to ensure they are on the curve and not the point at infinity, preventing certain attacks. The underlying `algorithms::ec` primitives handle these checks.
-   **Ephemeral Keys**: The use of ephemeral keys for each encapsulation ensures forward secrecy. Compromise of a long-term static private key does not compromise past session keys.
-   **Key Derivation Function (KDF)**: The raw ECDH shared secret (x-coordinate) is always processed by a strong KDF (HKDF with an appropriate hash function) to produce the final symmetric key. This step is crucial for cryptographic hygiene and security.
-   **Random Number Generation**: Secure generation of private key scalars is critical and relies on a `CryptoRng`.
-   **Compressed vs. Uncompressed Points**: While uncompressed points could also be used, this implementation opts for compressed points in the KEM ciphertext for bandwidth efficiency. The KDF input includes public keys, also in compressed format, to ensure consistent derivation.

This module provides robust and secure classical KEMs based on ECDH, suitable for integration into hybrid schemes or standalone use where classical PKE is appropriate.