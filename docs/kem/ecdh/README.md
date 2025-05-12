# Elliptic Curve Diffie-Hellman KEM (`kem/ecdh`)

This module is intended to implement Key Encapsulation Mechanisms (KEMs) based on the Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol. ECDH adapts the Diffie-Hellman concept to groups of points on an elliptic curve, offering smaller key sizes for equivalent security compared to traditional DH over finite fields.

**Note on Current Status:** The implementations in the provided codebase snapshot (`ecdh/mod.rs`) for `EcdhP256` and `EcdhP384` are placeholders. They define the necessary structs (`EcdhPublicKey`, `EcdhSecretKey`, etc.) and implement the `api::Kem` trait with dummy logic. This documentation describes the intended functionality based on this structure and common ECDH KEM practices.

## Algorithm Overview

ECDH key exchange allows two parties to establish a shared secret. A KEM variant can be constructed from ECDH.

-   **Parameters**: A specific elliptic curve (e.g., NIST P-256, P-384) and a base point `G` on that curve. These are public.
-   **Key Generation (Recipient)**:
    1.  Generates a private key `d_R` (a random scalar).
    2.  Computes their public key `Q_R = d_R * G` (elliptic curve point multiplication).
-   **Encapsulation (Sender)**:
    1.  Generates an ephemeral private key `d_S` (a random scalar).
    2.  Computes an ephemeral public key `Q_S = d_S * G`. This `Q_S` (or its x-coordinate) forms the KEM ciphertext.
    3.  Computes the shared secret point `P = d_S * Q_R = d_S * (d_R * G) = (d_S * d_R) * G`.
    4.  The actual shared secret key `K` is derived from the x-coordinate of `P` using a Key Derivation Function (KDF): `K = KDF(x_P)`.
-   **Decapsulation (Recipient)**:
    1.  Receives `Q_S` (the KEM ciphertext).
    2.  Computes the shared secret point `P = d_R * Q_S = d_R * (d_S * G) = (d_R * d_S) * G`.
    3.  Derives the shared secret key `K` using the same KDF: `K = KDF(x_P)`.

## Implemented Variants (Placeholders)

1.  **`EcdhP256`**:
    *   Intended to use the NIST P-256 (secp256r1) curve.
    *   **Public Key (`EcdhPublicKey`)**: Represents `Q_R`. Placeholder: `Vec<u8>` of 65 bytes (typical for uncompressed P-256 public key: 0x04 || x-coord || y-coord).
    *   **Secret Key (`EcdhSecretKey`)**: Represents `d_R`. Placeholder: `Vec<u8>` of 32 bytes.
    *   **Shared Secret (`EcdhSharedSecret`)**: Represents `K`. Placeholder: `Vec<u8>` of 32 bytes.
    *   **Ciphertext (`EcdhCiphertext`)**: Represents `Q_S`. Placeholder: `Vec<u8>` of 65 bytes.

2.  **`EcdhP384`**:
    *   Intended to use the NIST P-384 (secp384r1) curve.
    *   **Public Key (`EcdhPublicKey`)**: Placeholder: `Vec<u8>` of 97 bytes (uncompressed P-384).
    *   **Secret Key (`EcdhSecretKey`)**: Placeholder: `Vec<u8>` of 48 bytes.
    *   **Shared Secret (`EcdhSharedSecret`)**: Placeholder: `Vec<u8>` of 48 bytes.
    *   **Ciphertext (`EcdhCiphertext`)**: Placeholder: `Vec<u8>` of 97 bytes.

## `api::Kem` Trait Implementation

Both `EcdhP256` and `EcdhP384` structs implement the `api::Kem` trait:

-   `name()`: Returns "ECDH-P256" or "ECDH-P384".
-   `keypair()`: Placeholder generates random byte vectors for public and secret keys according to the expected sizes.
-   `public_key()`: Extracts the public key component.
-   `secret_key()`: Extracts the secret key component.
-   `encapsulate()`: Placeholder returns dummy ciphertext and shared secret.
-   `decapsulate()`: Placeholder returns a dummy shared secret.

## Security Considerations (General for ECDH)

-   **Curve Choice**: Use standard, well-vetted elliptic curves (like NIST P-curves or Curve25519).
-   **Point Validation**: Public keys received from external parties should be validated to ensure they are on the curve and not a point of small order, to prevent certain attacks (e.g., invalid curve attacks).
-   **Ephemeral Keys**: For KEM-like behavior ensuring forward secrecy, the sender's key pair (`d_S`, `Q_S`) should be ephemeral.
-   **Key Derivation Function (KDF)**: The x-coordinate of the shared secret point `P` should always be passed through a suitable KDF (e.g., HKDF) to produce the final cryptographic key(s). Direct use of the x-coordinate is generally insecure.
-   **Random Number Generation**: Secure generation of private keys (`d_R`, `d_S`) is critical.

Once fully implemented, this module would provide classical KEMs based on the widely adopted and efficient ECDH protocol, suitable for hybrid schemes.