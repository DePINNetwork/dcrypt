# ECDH-KEM with NIST P-521 (`kem::ecdh::p521`)

This module provides a Key Encapsulation Mechanism (KEM) based on the Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-521 curve (also known as secp521r1). The implementation is designed for security against timing attacks and adheres to best practices for key derivation, inspired by RFC 9180 (HPKE) for KDF usage.

This KEM variant utilizes compressed point format for ephemeral public keys, optimizing bandwidth efficiency during key exchange.

## Algorithm Details (`EcdhP521`)

The `EcdhP521` struct implements the `api::Kem` trait.

### Key Types

-   **`EcdhP521PublicKey`**:
    *   Wraps a `[u8; algorithms::ec::p521::P521_POINT_COMPRESSED_SIZE]`.
    *   Stores the P-521 public key point in compressed format (67 bytes).
-   **`EcdhP521SecretKey`**:
    *   Wraps a `SecretBuffer<{ algorithms::ec::p521::P521_SCALAR_SIZE }>`.
    *   Stores the P-521 private key scalar (66 bytes) securely.
    *   Implements `Zeroize` and `ZeroizeOnDrop`.
-   **`EcdhP521SharedSecret`**:
    *   Wraps an `api::Key` (from `dcrypt-api`).
    *   Stores the derived shared secret (default 64 bytes from HKDF-SHA512).
    *   Implements `Zeroize` and `ZeroizeOnDrop`.
-   **`EcdhP521Ciphertext`**:
    *   Wraps a `[u8; algorithms::ec::p521::P521_POINT_COMPRESSED_SIZE]`.
    *   Stores the compressed ephemeral public key used during encapsulation (67 bytes).

### KDF Details

-   **Shared Secret Derivation**: Uses HKDF with SHA-512 (`algorithms::ec::p521::kdf_hkdf_sha512_for_ecdh_kem`).
-   **IKM (Input Keying Material)**: The x-coordinate of the ECDH shared point.
-   **Salt**: The byte representation of the ephemeral public key (compressed format).
-   **Info**: A context string like `"ECDH-P521-KEM v2.0.0"` for domain separation. The version `v2.0.0` (defined as `KEM_KDF_VERSION` in `kem::ecdh::mod.rs`) signifies the use of compressed points in the KDF context.
-   **Output Length**: `algorithms::ec::p521::P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE` (64 bytes).

### Operations

1.  **`keypair(rng)`**:
    *   Generates a P-521 key pair using `algorithms::ec::p521::generate_keypair`.
    *   The public key is serialized in compressed format.
    *   The private key scalar is stored securely.

2.  **`encapsulate(rng, public_key_recipient)`**:
    *   Deserializes and validates the recipient's compressed public key.
    *   Generates an ephemeral P-521 key pair `(ephemeral_scalar, ephemeral_point)`.
    *   The `ephemeral_point` is serialized in compressed format to become the `EcdhP521Ciphertext`.
    *   Computes the ECDH shared point: `shared_point = ephemeral_scalar * public_key_recipient_point`.
    *   Validates that `shared_point` is not the point at infinity.
    *   Extracts the x-coordinate of `shared_point` as IKM for the KDF.
    *   Constructs the KDF input by concatenating the x-coordinate, the serialized ephemeral public key, and the recipient's public key (all in compressed format).
    *   Derives the `EcdhP521SharedSecret` using HKDF-SHA512.
    *   Ensures the ephemeral scalar is zeroized.

3.  **`decapsulate(secret_key_recipient, ciphertext_ephemeral_pk)`**:
    *   Deserializes the ephemeral public key point from the `ciphertext_ephemeral_pk`. Validates it's not identity.
    *   Deserializes the recipient's secret key scalar.
    *   Computes the ECDH shared point: `shared_point = secret_key_recipient_scalar * ephemeral_pk_point`.
    *   Validates that `shared_point` is not the point at infinity.
    *   Extracts the x-coordinate.
    *   Recomputes the recipient's public key (for KDF input consistency).
    *   Constructs the KDF input identically to encapsulation.
    *   Re-derives the `EcdhP521SharedSecret` using HKDF-SHA512.

This KEM offers a very high level of classical security and forward secrecy.