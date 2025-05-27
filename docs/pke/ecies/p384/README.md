# ECIES with P-384 and AES-256-GCM (`pke::ecies::p384`)

This module provides an implementation of the Elliptic Curve Integrated Encryption Scheme (ECIES) specifically configured to use:

-   **Elliptic Curve**: NIST P-384 (also known as secp384r1).
-   **Key Derivation Function (KDF)**: HKDF with SHA-384.
-   **Authenticated Encryption with Associated Data (AEAD)**: AES-256-GCM.

This combination provides a high level of security for asymmetric encryption, leveraging well-standardized primitives.

## Algorithm Details (`EciesP384`)

The `EciesP384` struct implements the `api::traits::Pke` trait.

### Key Types

-   **`EciesP384PublicKey`**:
    *   Wraps a `[u8; algorithms::ec::p384::P384_POINT_UNCOMPRESSED_SIZE]`.
    *   Stores the P-384 public key point in uncompressed format (97 bytes: `0x04 || X-coordinate || Y-coordinate`).
-   **`EciesP384SecretKey`**:
    *   Wraps a `[u8; algorithms::ec::p384::P384_SCALAR_SIZE]`.
    *   Stores the P-384 private key scalar (48 bytes).
    *   Implements `Zeroize` and `ZeroizeOnDrop` for secure memory handling.

### Ciphertext

-   The `Ciphertext` type is `Vec<u8>`.
-   It represents the serialized form of `EciesCiphertextComponents` (defined in the parent `pke::ecies` module), which includes:
    1.  **Ephemeral Public Key (`R`)**: The sender's temporary P-384 public key, serialized in uncompressed format (97 bytes).
    2.  **AEAD Nonce (`N`)**: A 12-byte nonce for AES-256-GCM (the recommended size).
    3.  **AEAD Ciphertext+Tag (`C||T`)**: The output of AES-256-GCM encryption, including the encrypted message and the 16-byte GCM authentication tag.

### Operations

1.  **`keypair(rng)`**:
    *   Generates a P-384 key pair using `algorithms::ec::p384::generate_keypair`.
    *   The public key is serialized in uncompressed format.
    *   The private key is the raw scalar.

2.  **`encrypt(pk_recipient, plaintext, aad, rng)`**:
    *   Deserializes the recipient's uncompressed public key point. Validates it's not the point at infinity.
    *   Generates an ephemeral P-384 key pair `(ephemeral_sk_scalar, ephemeral_pk_point)`.
    *   Performs ECDH: `shared_point = ephemeral_sk_scalar * pk_recipient_point`. Validates that `shared_point` is not identity.
    *   Extracts the x-coordinate (`z_bytes`) of `shared_point`.
    *   Derives the symmetric AEAD key using `derive_symmetric_key_hkdf_sha384`:
        *   **IKM**: `z_bytes`.
        *   **Salt**: Bytes of the uncompressed `ephemeral_pk_point`.
        *   **Info**: A context string like `"ECIES-P384-HKDF-SHA384-AES256GCM-KeyMaterial"`.
        *   **Output Length**: `AES256GCM_KEY_LEN` (32 bytes).
    *   Generates a random 12-byte nonce for AES-256-GCM.
    *   Encrypts the `plaintext` with the derived key, nonce, and `aad` using `algorithms::aead::gcm::Gcm<Aes256>`.
    *   Serializes the `ephemeral_pk_point` (uncompressed), AEAD nonce, and AEAD ciphertext+tag into the final ECIES ciphertext using `EciesCiphertextComponents::serialize()`.
    *   Ensures `ephemeral_sk_scalar`, `z_bytes`, and `derived_key_material` are zeroized.

3.  **`decrypt(sk_recipient, ciphertext_bytes, aad)`**:
    *   Deserializes `ciphertext_bytes` into `EciesCiphertextComponents`.
    *   Deserializes the ephemeral public key point from the components. Validates it's not identity.
    *   Deserializes the recipient's secret key scalar.
    *   Performs ECDH: `shared_point = sk_recipient_scalar * ephemeral_pk_point`. Validates that `shared_point` is not identity.
    *   Extracts the x-coordinate (`z_bytes`).
    *   Re-derives the symmetric AEAD key using `derive_symmetric_key_hkdf_sha384` with the same parameters as in encryption (using the received ephemeral public key bytes as salt).
    *   Deserializes the AEAD nonce from the components.
    *   Decrypts the AEAD ciphertext+tag using `algorithms::aead::gcm::Gcm<Aes256>`.
    *   If AEAD decryption and authentication succeed, returns the plaintext. Otherwise, returns an error (specifically `PkeError::DecryptionFailed("AEAD authentication failed")` which maps to `ApiError::DecryptionFailed`).
    *   Ensures `z_bytes` and `derived_key_material` are zeroized.

This ECIES variant using P-384 and AES-256-GCM provides a high level of classical security.