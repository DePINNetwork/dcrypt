# ECIES with P-256 and ChaCha20Poly1305 (`pke::ecies::p256`)

This module provides an implementation of the Elliptic Curve Integrated Encryption Scheme (ECIES) specifically configured to use:

-   **Elliptic Curve**: NIST P-256 (also known as secp256r1 or prime256v1).
-   **Key Derivation Function (KDF)**: HKDF with SHA-256.
-   **Authenticated Encryption with Associated Data (AEAD)**: ChaCha20Poly1305.

This combination offers strong, modern asymmetric encryption suitable for various applications.

## Algorithm Details (`EciesP256`)

The `EciesP256` struct implements the `api::traits::Pke` trait.

### Key Types

-   **`EciesP256PublicKey`**:
    *   Wraps a `[u8; algorithms::ec::p256::P256_POINT_UNCOMPRESSED_SIZE]`.
    *   Stores the P-256 public key point in uncompressed format (65 bytes: `0x04 || X-coordinate || Y-coordinate`).
-   **`EciesP256SecretKey`**:
    *   Wraps a `[u8; algorithms::ec::p256::P256_SCALAR_SIZE]`.
    *   Stores the P-256 private key scalar (32 bytes).
    *   Implements `Zeroize` and `ZeroizeOnDrop` for secure memory handling.

### Ciphertext

-   The `Ciphertext` type is `Vec<u8>`.
-   It represents the serialized form of `EciesCiphertextComponents` (defined in the parent `pke::ecies` module), which includes:
    1.  **Ephemeral Public Key (`R`)**: The sender's temporary P-256 public key, serialized in uncompressed format (65 bytes).
    2.  **AEAD Nonce (`N`)**: A 12-byte nonce for ChaCha20Poly1305.
    3.  **AEAD Ciphertext+Tag (`C||T`)**: The output of ChaCha20Poly1305 encryption, which includes the encrypted message and the 16-byte Poly1305 authentication tag.

### Operations

1.  **`keypair(rng)`**:
    *   Generates a P-256 key pair using `algorithms::ec::p256::generate_keypair`.
    *   The public key is serialized in uncompressed format.
    *   The private key is the raw scalar.

2.  **`encrypt(pk_recipient, plaintext, aad, rng)`**:
    *   Deserializes the recipient's uncompressed public key point. Validates it's not the point at infinity.
    *   Generates an ephemeral P-256 key pair `(ephemeral_sk_scalar, ephemeral_pk_point)`.
    *   Performs ECDH: `shared_point = ephemeral_sk_scalar * pk_recipient_point`. Validates that `shared_point` is not identity.
    *   Extracts the x-coordinate (`z_bytes`) of `shared_point`.
    *   Derives the symmetric AEAD key using `derive_symmetric_key_hkdf_sha256`:
        *   **IKM**: `z_bytes`.
        *   **Salt**: Bytes of the uncompressed `ephemeral_pk_point`.
        *   **Info**: A context string like `"ECIES-P256-HKDF-SHA256-ChaCha20Poly1305-KeyMaterial"`.
        *   **Output Length**: `CHACHA20POLY1305_KEY_LEN` (32 bytes).
    *   Generates a random 12-byte nonce for ChaCha20Poly1305.
    *   Encrypts the `plaintext` with the derived key, nonce, and `aad` using `algorithms::aead::chacha20poly1305::ChaCha20Poly1305`.
    *   Serializes the `ephemeral_pk_point` (uncompressed), AEAD nonce, and AEAD ciphertext+tag into the final ECIES ciphertext using `EciesCiphertextComponents::serialize()`.
    *   Ensures `ephemeral_sk_scalar`, `z_bytes`, and `derived_key_material` are zeroized.

3.  **`decrypt(sk_recipient, ciphertext_bytes, aad)`**:
    *   Deserializes `ciphertext_bytes` into `EciesCiphertextComponents`.
    *   Deserializes the ephemeral public key point from the components. Validates it's not identity.
    *   Deserializes the recipient's secret key scalar.
    *   Performs ECDH: `shared_point = sk_recipient_scalar * ephemeral_pk_point`. Validates that `shared_point` is not identity.
    *   Extracts the x-coordinate (`z_bytes`).
    *   Re-derives the symmetric AEAD key using `derive_symmetric_key_hkdf_sha256` with the same parameters as in encryption (using the received ephemeral public key bytes as salt).
    *   Deserializes the AEAD nonce from the components.
    *   Decrypts the AEAD ciphertext+tag using `algorithms::aead::chacha20poly1305::ChaCha20Poly1305`.
    *   If AEAD decryption and authentication succeed, returns the plaintext. Otherwise, returns an error (specifically `PkeError::DecryptionFailed("AEAD authentication failed")` which maps to `ApiError::DecryptionFailed`).
    *   Ensures `z_bytes` and `derived_key_material` are zeroized.

This construction provides robust public-key encryption with forward secrecy (due to ephemeral keys) and authentication.