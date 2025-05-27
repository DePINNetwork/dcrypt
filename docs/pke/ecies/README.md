# Elliptic Curve Integrated Encryption Scheme (ECIES)

This module (`pke::ecies`) implements the Elliptic Curve Integrated Encryption Scheme (ECIES). ECIES is a hybrid encryption scheme that combines Elliptic Curve Diffie-Hellman (ECDH) for asymmetric key agreement with a Key Derivation Function (KDF) and a symmetric Authenticated Encryption with Associated Data (AEAD) cipher for efficient bulk encryption.

It provides strong security properties, including confidentiality and (typically) authenticity of the encrypted messages.

## General ECIES Workflow

1.  **Key Pair Generation (Recipient)**:
    *   The recipient has a static elliptic curve key pair `(sk_R, PK_R)`, where `sk_R` is a scalar (private key) and `PK_R` is a point on the curve (public key). These keys are long-term.

2.  **Encryption (Sender)**:
    To encrypt a message `M` for the recipient with public key `PK_R`:
    *   Generate an ephemeral (temporary) ECDH key pair `(sk_E, PK_E)`. This key pair is used only for this encryption operation.
    *   Perform an ECDH key agreement between the ephemeral secret key `sk_E` and the recipient's static public key `PK_R` to derive a shared secret point `Z = sk_E * PK_R`.
    *   Extract a byte string from `Z` (commonly the x-coordinate, `z_bytes`).
    *   Use a Key Derivation Function (KDF), such as HKDF, to derive a symmetric key `K_sym` from `z_bytes`. The ephemeral public key `PK_E` (or its byte representation) is often used as salt or context information for the KDF. This binds `K_sym` to this specific ECIES instance and the ephemeral key.
        `K_sym = KDF(salt=PK_E_bytes, ikm=z_bytes, info=context_string)`
    *   Encrypt the plaintext `M` using `K_sym` and an AEAD cipher (e.g., ChaCha20Poly1305, AES-GCM) with a fresh, unique nonce `N`. Optionally, Associated Additional Data (AAD) can be included to be authenticated along with the plaintext. This produces an AEAD ciphertext `C_aead` (which includes the actual encrypted data and an authentication tag).
    *   The final ECIES ciphertext is typically a composition of `PK_E` (so the recipient can re-derive `Z`), `N`, and `C_aead`. The `EciesCiphertextComponents` struct in this implementation serializes these as: `R_len (1B) || R_bytes || N_len (1B) || N_bytes || CT_len (4B) || (Ciphertext_AEAD || Tag_AEAD)`.

3.  **Decryption (Recipient)**:
    To decrypt an ECIES ciphertext (which contains `PK_E_bytes`, `N_bytes`, and `C_aead_bytes`) using their static private key `sk_R`:
    *   Deserialize `PK_E_bytes` to the ephemeral public key point `PK_E`. Validate `PK_E` to ensure it's a valid point on the curve.
    *   Perform an ECDH key agreement between the recipient's static secret key `sk_R` and the sender's ephemeral public key `PK_E` to derive the same shared secret point `Z = sk_R * PK_E`.
    *   Extract `z_bytes` from `Z`.
    *   Use the same KDF with `z_bytes`, `PK_E_bytes` (as salt/context), and the same context string to re-derive the symmetric key `K_sym`.
    *   Deserialize `N_bytes` to the nonce `N`.
    *   Decrypt `C_aead_bytes` using `K_sym`, `N`, and the same AAD (if any) used during encryption. If the AEAD tag verifies successfully, the original plaintext `M` is recovered. Otherwise, decryption fails, indicating tampering or use of an incorrect key.

## Implemented Variants

This module provides specific ECIES instantiations:

1.  **ECIES with P-256 (`pke::ecies::p256`)**:
    *   Uses NIST P-256 curve, HKDF-SHA256, and ChaCha20Poly1305.
    *   Refer to `dcrypt_docs/pke/ecies/p256/README.md`.

2.  **ECIES with P-384 (`pke::ecies::p384`)**:
    *   Uses NIST P-384 curve, HKDF-SHA384, and AES-256-GCM.
    *   Refer to `dcrypt_docs/pke/ecies/p384/README.md`.

## Shared Components

-   **`derive_symmetric_key_hkdf_sha256 / _sha384`**: Internal helper functions using `algorithms::kdf::hkdf::Hkdf` for deriving the symmetric AEAD key. The shared secret `z_bytes` (x-coordinate of the ECDH shared point) is used as the Input Keying Material (IKM), and the `ephemeral_pk_bytes` (serialized ephemeral public key) is used as the salt for HKDF. A context-specific `info` string further refines the key derivation.
-   **`EciesCiphertextComponents`**: A private struct used by both P-256 and P-384 implementations to structure and serialize/deserialize the components of an ECIES ciphertext.
    *   **Serialization Format**: The components (ephemeral public key `R`, AEAD nonce `N`, and AEAD ciphertext+tag `C||T`) are serialized with length prefixes to allow unambiguous parsing:
        `R_len (1 byte) || R_bytes || N_len (1 byte) || N_bytes || CT_len (4 bytes, big-endian) || (Ciphertext_AEAD || Tag_AEAD)`
-   **Constants**: Define key and nonce lengths for the chosen AEAD ciphers (e.g., `CHACHA20POLY1305_KEY_LEN`, `AES256GCM_NONCE_LEN`).

These components ensure a consistent structure for ECIES operations across different curve and AEAD choices.