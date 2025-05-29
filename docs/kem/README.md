# Key Encapsulation Mechanisms (`kem`)

The `kem` crate is responsible for implementing various Key Encapsulation Mechanisms (KEMs). KEMs are cryptographic schemes used to securely establish shared secrets between parties, typically involving a public-key component. One party (sender) uses the recipient's public key to generate a shared secret and an "encapsulation" (ciphertext) of that secret. The recipient then uses their private key to "decapsulate" the ciphertext and recover the same shared secret.

This crate provides implementations for both traditional (classical) KEMs and post-quantum KEMs.

**Note on Current Status:** While the ECDH-based KEMs (`EcdhP256`, `EcdhP384`, `EcdhP521`) are described with significant implementation detail (using compressed points and specific KDFs), many other KEMs listed (RSA, DH, and PQC KEMs like Kyber, NTRU, Saber, McEliece) are currently placeholders in the codebase snapshot. They define the necessary structs and implement the `api::Kem` trait with dummy logic, indicating the intended structure rather than full cryptographic functionality.

## Core Trait

All KEMs in this crate are expected to implement the `api::Kem` trait, which defines the standard interface:

-   `type PublicKey`, `type SecretKey`, `type SharedSecret`, `type Ciphertext`, `type KeyPair`
-   `name() -> &'static str`
-   `keypair<R: CryptoRng + RngCore>(...) -> Result<Self::KeyPair>`
-   `public_key(keypair: &Self::KeyPair) -> Self::PublicKey`
-   `secret_key(keypair: &Self::KeyPair) -> Self::SecretKey`
-   `encapsulate<R: CryptoRng + RngCore>(...) -> Result<(Self::Ciphertext, Self::SharedSecret)>`
-   `decapsulate(...) -> Result<Self::SharedSecret>`

## Implemented/Planned KEMs

### Traditional KEMs

1.  **RSA-KEM (`rsa`)**
    *   **Description**: KEM based on the RSA public-key cryptosystem.
    *   **Variants**: `RsaKem2048`, `RsaKem4096`.
    *   **Files**: `dcrypt_docs/kem/rsa/README.md`
    *   **Status**: Placeholder implementations.

2.  **Diffie-Hellman KEM (`dh`)**
    *   **Description**: KEM based on the Diffie-Hellman key exchange protocol over finite fields (MODP groups).
    *   **Variants**: `Dh2048`.
    *   **Files**: `dcrypt_docs/kem/dh/README.md`
    *   **Status**: Placeholder implementation.

3.  **ECDH-KEM (Elliptic Curve Diffie-Hellman KEM) (`ecdh`)**
    *   **Description**: KEM based on Diffie-Hellman key exchange over elliptic curves. Uses compressed points for ciphertexts and HKDF for key derivation.
    *   **Variants**:
        *   `EcdhP256` (using NIST P-256 curve, HKDF-SHA256)
        *   `EcdhP384` (using NIST P-384 curve, HKDF-SHA384)
        *   `EcdhP521` (using NIST P-521 curve, HKDF-SHA512)
    *   **Files**: `dcrypt_docs/kem/ecdh/README.md` (with links to P256, P384, P521 specifics)
    *   **Status**: Functionally implemented with details for KDF and point compression.

### Post-Quantum KEMs

1.  **Kyber (`kyber`)**
    *   **Description**: A lattice-based KEM chosen by NIST for standardization in the PQC project.
    *   **Variants**: `Kyber512`, `Kyber768`, `Kyber1024`.
    *   **Files**: `dcrypt_docs/kem/kyber/README.md`
    *   **Status**: Placeholder implementations. Parameters are defined in `dcrypt-params`.

2.  **NTRU (`ntru`)**
    *   **Description**: A lattice-based KEM. The snapshot includes `NtruHps` and `NtruEes`.
    *   **Files**: `dcrypt_docs/kem/ntru/README.md`
    *   **Status**: Placeholder implementations. Parameters are defined in `dcrypt-params`.

3.  **SABER (`saber`)**
    *   **Description**: A lattice-based KEM, another finalist in the NIST PQC standardization process.
    *   **Variants**: `LightSaber`, `Saber`, `FireSaber`.
    *   **Files**: `dcrypt_docs/kem/saber/README.md`
    *   **Status**: Placeholder implementations. Parameters are defined in `dcrypt-params`.

4.  **McEliece (`mceliece`)**
    *   **Description**: A code-based KEM, one of the oldest PQC schemes, also selected by NIST for standardization.
    *   **Variants**: `McEliece348864`, `McEliece6960119`.
    *   **Files**: `dcrypt_docs/kem/mceliece/README.md`
    *   **Status**: Placeholder implementations. Parameters are defined in `dcrypt-params`.

## Error Handling

The `kem` crate defines its own `Error` enum (`dcrypt_docs/kem/error/README.md`) for KEM-specific errors (e.g., `KeyGeneration`, `Encapsulation`, `Decapsulation`, `InvalidKey`, `InvalidCiphertext`). These errors can be converted from `algorithms::Error` and into `api::Error`. Validation utilities specific to KEMs are also provided.

## Usage

Once fully implemented, KEMs would be used as follows (conceptual example using `EcdhP256`):

```rust
use dcrypt_kem::ecdh::EcdhP256; // Example
use dcrypt_api::Kem;
use rand::rngs::OsRng;
use dcrypt_api::error::Result as ApiResult; // Use API's Result type

fn kem_usage_example() -> ApiResult<()> {
    let mut rng = OsRng;

    // 1. Generate recipient's key pair
    let (public_key, secret_key) = EcdhP256::keypair(&mut rng)?;

    // 2. Sender encapsulates a shared secret using recipient's public key
    let (ciphertext, shared_secret_sender) = EcdhP256::encapsulate(&mut rng, &public_key)?;

    // 3. Recipient decapsulates the ciphertext using their secret key
    let shared_secret_receiver = EcdhP256::decapsulate(&secret_key, &ciphertext)?;

    // Both parties now have the same shared secret
    assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref());

    println!("ECDH-P256 KEM operation successful. Shared secret established.");
    Ok(())
}