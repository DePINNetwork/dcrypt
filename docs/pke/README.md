# Public Key Encryption (`pke`)

The `pke` (Public Key Encryption) crate provides implementations of public-key encryption schemes, allowing one party to encrypt a message such that only a specific recipient with the corresponding private key can decrypt it. This crate focuses on schemes that combine asymmetric and symmetric cryptography for efficiency and security, often known as hybrid encryption schemes.

Currently, it primarily features implementations of ECIES (Elliptic Curve Integrated Encryption Scheme).

## Core Functionality

The PKE schemes in this crate are designed to:

1.  **Generate Key Pairs**: Produce a public key (for encryption) and a corresponding private key (for decryption).
2.  **Encrypt Data**: Take a recipient's public key and a plaintext message (optionally with Associated Additional Data - AAD) to produce a ciphertext.
3.  **Decrypt Data**: Take a recipient's private key and a ciphertext (optionally with AAD) to recover the original plaintext, if the ciphertext is valid and was encrypted for this private key.

All PKE schemes implemented here are expected to adhere to the `api::traits::Pke` trait, which is defined in the `dcrypt-api` crate.

## Implemented Schemes

### ECIES (Elliptic Curve Integrated Encryption Scheme) (`pke::ecies`)

ECIES is a hybrid encryption scheme that combines Elliptic Curve Diffie-Hellman (ECDH) for key agreement with a Key Derivation Function (KDF) and a symmetric Authenticated Encryption with Associated Data (AEAD) cipher for the actual data encryption.

-   **Key Agreement**: An ephemeral ECDH key pair is generated by the sender. The ephemeral public key is combined with the recipient's static public key to derive a shared secret.
-   **Key Derivation**: The shared secret from ECDH (typically its x-coordinate) is passed through a KDF (e.g., HKDF) to derive a symmetric encryption key for the AEAD cipher. The ephemeral public key is often used as salt or info for the KDF.
-   **Data Encryption**: The plaintext message is encrypted using the derived symmetric key and an AEAD cipher (e.g., ChaCha20Poly1305 or AES-GCM).
-   **Ciphertext**: The ECIES ciphertext typically consists of the sender's ephemeral public key and the AEAD ciphertext (which includes the symmetric nonce and the encrypted data + authentication tag).

The `pke` crate provides the following ECIES variants:

1.  **`EciesP256` (`pke::ecies::p256`)**:
    *   **Elliptic Curve**: NIST P-256 (secp256r1).
    *   **KDF**: HKDF with SHA-256.
    *   **AEAD**: ChaCha20Poly1305.
    *   **Public Key**: `EciesP256PublicKey` (65-byte uncompressed P-256 point).
    *   **Secret Key**: `EciesP256SecretKey` (32-byte P-256 scalar).
    *   **Ciphertext Format**: Serialized `EciesCiphertextComponents` containing the ephemeral public key (uncompressed P-256 point), AEAD nonce (12 bytes for ChaCha20Poly1305), and the AEAD ciphertext+tag.
    *   See `dcrypt_docs/pke/ecies/README.md` and `dcrypt_docs/pke/ecies/p256/README.md` for more details.

2.  **`EciesP384` (`pke::ecies::p384`)**:
    *   **Elliptic Curve**: NIST P-384 (secp384r1).
    *   **KDF**: HKDF with SHA-384.
    *   **AEAD**: AES-256-GCM.
    *   **Public Key**: `EciesP384PublicKey` (97-byte uncompressed P-384 point).
    *   **Secret Key**: `EciesP384SecretKey` (48-byte P-384 scalar).
    *   **Ciphertext Format**: Serialized `EciesCiphertextComponents` containing the ephemeral public key (uncompressed P-384 point), AEAD nonce (12 bytes for AES-GCM), and the AEAD ciphertext+tag.
    *   See `dcrypt_docs/pke/ecies/README.md` and `dcrypt_docs/pke/ecies/p384/README.md` for more details.

3.  **`EciesP521` (`pke::ecies::p521`)**:
    *   **Elliptic Curve**: NIST P-521 (secp521r1).
    *   **KDF**: HKDF with SHA-512.
    *   **AEAD**: AES-256-GCM.
    *   **Public Key**: `EciesP521PublicKey` (133-byte uncompressed P-521 point).
    *   **Secret Key**: `EciesP521SecretKey` (66-byte P-521 scalar).
    *   **Ciphertext Format**: Serialized `EciesCiphertextComponents` containing the ephemeral public key (uncompressed P-521 point), AEAD nonce (12 bytes for AES-GCM), and the AEAD ciphertext+tag.
    *   See `dcrypt_docs/pke/ecies/README.md` and `dcrypt_docs/pke/ecies/p521/README.md` for more details.

## Error Handling

The `pke` crate defines its own `Error` enum (`pke::error::Error`) for PKE-specific errors. These errors can be converted to and from the core `api::error::Error` type. Refer to `dcrypt_docs/pke/error.md` for details.

## Usage Example (ECIES P-256)

```rust
use dcrypt_pke::ecies::EciesP256;
use dcrypt_api::traits::Pke; // The core PKE trait
use rand::rngs::OsRng;
use dcrypt_api::error::Result as ApiResult; // Using the API's Result type

fn ecies_p256_example() -> ApiResult<()> {
    let mut rng = OsRng;

    // 1. Generate Recipient's Key Pair
    let (recipient_pk, recipient_sk) = EciesP256::keypair(&mut rng)?;
    // In a real application, recipient_pk would be distributed, recipient_sk kept secret.

    // 2. Encrypt a message for the recipient
    let plaintext = b"This is a secret message for ECIES!";
    let aad = Some(b"Optional Associated Data");

    let ciphertext_vec = EciesP256::encrypt(
        &recipient_pk,
        plaintext,
        aad,
        &mut rng,
    )?;

    // 3. Decrypt the message using the recipient's secret key
    let decrypted_plaintext_vec = EciesP256::decrypt(
        &recipient_sk,
        &ciphertext_vec, // Ciphertext type for ECIES is Vec<u8>
        aad,
    )?;

    // 4. Verify
    assert_eq!(plaintext, decrypted_plaintext_vec.as_slice());
    println!("ECIES P-256 Encryption/Decryption successful!");

    Ok(())
}

// To run:
// fn main() {
//     if let Err(e) = ecies_p256_example() {
//         eprintln!("ECIES P-256 example failed: {}", e);
//     }
// }