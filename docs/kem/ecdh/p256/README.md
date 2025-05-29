
---

### `kem` Crate Documentation Updates

#### **COMPLETE FILE:** `docs/kem/ecdh/p256/README.md`
```markdown
# ECDH-KEM with NIST P-256 (`kem::ecdh::p256`)

This module provides a Key Encapsulation Mechanism (KEM) based on the Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-256 curve (also known as secp256r1 or prime256v1). The implementation is designed for security against timing attacks and adheres to best practices for key derivation, inspired by RFC 9180 (HPKE) for KDF usage.

This KEM variant utilizes compressed point format for ephemeral public keys, optimizing bandwidth efficiency during key exchange.

## Algorithm Details (`EcdhP256`)

The `EcdhP256` struct implements the `api::Kem` trait.

### Key Types

-   **`EcdhP256PublicKey`**:
    *   Wraps a `[u8; algorithms::ec::p256::P256_POINT_COMPRESSED_SIZE]`.
    *   Stores the P-256 public key point in compressed format (33 bytes).
-   **`EcdhP256SecretKey`**:
    *   Wraps a `SecretBuffer<{ algorithms::ec::p256::P256_SCALAR_SIZE }>`.
    *   Stores the P-256 private key scalar (32 bytes) securely.
    *   Implements `Zeroize` and `ZeroizeOnDrop`.
-   **`EcdhP256SharedSecret`**:
    *   Wraps an `api::Key` (from `dcrypt-api`).
    *   Stores the derived shared secret (default 32 bytes from HKDF-SHA256).
    *   Implements `Zeroize` and `ZeroizeOnDrop`.
-   **`EcdhP256Ciphertext`**:
    *   Wraps a `[u8; algorithms::ec::p256::P256_POINT_COMPRESSED_SIZE]`.
    *   Stores the compressed ephemeral public key used during encapsulation (33 bytes).

### KDF Details

-   **Shared Secret Derivation**: Uses HKDF with SHA-256 (`algorithms::ec::p256::kdf_hkdf_sha256_for_ecdh_kem`).
-   **IKM (Input Keying Material)**: The x-coordinate of the ECDH shared point.
-   **Salt**: The byte representation of the ephemeral public key (compressed format).
-   **Info**: A context string like `"ECDH-P256-KEM v2.0.0"` for domain separation. The version `v2.0.0` (defined as `KEM_KDF_VERSION` in `kem::ecdh::mod.rs`) signifies the use of compressed points in the KDF context.
-   **Output Length**: `algorithms::ec::p256::P256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE` (32 bytes).

### Operations

1.  **`keypair(rng)`**:
    *   Generates a P-256 key pair using `algorithms::ec::p256::generate_keypair`.
    *   The public key is serialized in compressed format.
    *   The private key scalar is stored securely.

2.  **`encapsulate(rng, public_key_recipient)`**:
    *   Deserializes and validates the recipient's compressed public key.
    *   Generates an ephemeral P-256 key pair `(ephemeral_scalar, ephemeral_point)`.
    *   The `ephemeral_point` is serialized in compressed format to become the `EcdhP256Ciphertext`.
    *   Computes the ECDH shared point: `shared_point = ephemeral_scalar * public_key_recipient_point`.
    *   Validates that `shared_point` is not the point at infinity.
    *   Extracts the x-coordinate of `shared_point` as IKM for the KDF.
    *   Constructs the KDF input by concatenating the x-coordinate, the serialized ephemeral public key, and the recipient's public key (all in compressed format).
    *   Derives the `EcdhP256SharedSecret` using HKDF-SHA256.
    *   Ensures the ephemeral scalar is zeroized.

3.  **`decapsulate(secret_key_recipient, ciphertext_ephemeral_pk)`**:
    *   Deserializes the ephemeral public key point from the `ciphertext_ephemeral_pk`. Validates it's not identity.
    *   Deserializes the recipient's secret key scalar.
    *   Computes the ECDH shared point: `shared_point = secret_key_recipient_scalar * ephemeral_pk_point`.
    *   Validates that `shared_point` is not the point at infinity.
    *   Extracts the x-coordinate.
    *   Recomputes the recipient's public key (for KDF input consistency).
    *   Constructs the KDF input identically to encapsulation.
    *   Re-derives the `EcdhP256SharedSecret` using HKDF-SHA256.

This KEM offers strong classical security and forward secrecy due to the use of ephemeral keys.