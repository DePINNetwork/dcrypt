# Digital Signature Schemes (`sign`)

The `sign` crate is dedicated to implementing various digital signature schemes. Digital signatures provide message authenticity (proof of origin), integrity (proof that the message has not been altered), and non-repudiation (the signer cannot deny having signed the message).

This crate aims to provide implementations for both traditional (classical) signature algorithms and post-quantum signature algorithms.

**Note on Current Status:** While ECDSA implementations for P-256, P-384, and P-521 are detailed, many other signature schemes (both traditional and PQC) listed in the snapshot are currently placeholders. They define the necessary structs for keys and signatures and implement the `api::Signature` trait with dummy logic, indicating the intended structure rather than full cryptographic functionality.

## Core Trait

All signature schemes in this crate are expected to implement the `api::Signature` trait, which defines the standard interface:

-   `type PublicKey`, `type SecretKey`, `type SignatureData`, `type KeyPair`
-   `name() -> &'static str`
-   `keypair<R: CryptoRng + RngCore>(...) -> Result<Self::KeyPair>`
-   `public_key(keypair: &Self::KeyPair) -> Self::PublicKey`
-   `secret_key(keypair: &Self::KeyPair) -> Self::SecretKey`
-   `sign(message: &[u8], secret_key: &Self::SecretKey) -> Result<Self::SignatureData>`
-   `verify(message: &[u8], signature: &Self::SignatureData, public_key: &Self::PublicKey) -> Result<()>`
-   `batch_sign(...)` and `batch_verify(...)` (with default implementations).

## Implemented/Planned Signature Schemes

### Traditional Signature Schemes (`dcrypt_docs/sign/traditional/README.md`)

1.  **EdDSA (`traditional::eddsa`)**
    *   **`Ed25519`**: EdDSA signature scheme using Curve25519.
    *   **Status**: Placeholder implementation.

2.  **ECDSA (Elliptic Curve Digital Signature Algorithm) (`traditional::ecdsa`)**
    *   **Description**: Widely used signature scheme based on elliptic curves. DCRYPT implementations use deterministic nonce generation (RFC 6979 + hedging).
    *   **Variants**:
        *   `EcdsaP256` (NIST P-256 curve with SHA-256)
        *   `EcdsaP384` (NIST P-384 curve with SHA-384)
        *   `EcdsaP521` (NIST P-521 curve with SHA-512)
    *   **Status**: Implemented for P-256, P-384, and P-521.

3.  **RSA Signatures (`traditional::rsa`)**
    *   **Description**: Signature schemes based on the RSA cryptosystem.
    *   **Variants**: `RsaPss`, `RsaPkcs1`.
    *   **Status**: Placeholder implementations.

4.  **DSA (Digital Signature Algorithm) (`traditional::dsa`)**
    *   **Description**: Older standard for digital signatures.
    *   **Status**: Placeholder implementation.

### Post-Quantum Signature Schemes (`dcrypt_docs/sign/pq/README.md`)

1.  **Dilithium (`pq::dilithium`)**
    *   **Description**: A lattice-based signature scheme, NIST PQC selected.
    *   **Variants**: `Dilithium2`, `Dilithium3`, `Dilithium5`.
    *   **Status**: Placeholder implementations. Parameters in `dcrypt-params`.

2.  **Falcon (`pq::falcon`)**
    *   **Description**: A lattice-based signature scheme (NTRU lattices), NIST PQC selected. Known for compact signatures.
    *   **Variants**: `Falcon512`, `Falcon1024`.
    *   **Status**: Placeholder implementations. Parameters in `dcrypt-params`.

3.  **SPHINCS+ (`pq::sphincs`)**
    *   **Description**: A stateless hash-based signature scheme, NIST PQC selected. Relies on hash function security.
    *   **Variants**: `SphincsSha2`, `SphincsShake`.
    *   **Status**: Placeholder implementations. Parameters in `dcrypt-params`.

4.  **Rainbow (`pq::rainbow`)**
    *   **Description**: A multivariate quadratic signature scheme, NIST PQC selected.
    *   **Variants**: `RainbowI`, `RainbowIII`, `RainbowV`.
    *   **Status**: Placeholder implementations. Parameters in `dcrypt-params`.

## Usage

Once fully implemented, signature schemes would be used as follows (conceptual example using `EcdsaP256`):

```rust
use dcrypt_sign::traditional::ecdsa::EcdsaP256; // Example
use dcrypt_api::Signature;
use rand::rngs::OsRng;
use dcrypt_api::error::Result as ApiResult; // Use API's Result type

fn signature_usage_example() -> ApiResult<()> {
    let mut rng = OsRng;
    let message = b"This is a message to be signed.";

    // 1. Generate key pair
    let (public_key, secret_key) = EcdsaP256::keypair(&mut rng)?;

    // 2. Sign the message
    let signature = EcdsaP256::sign(message, &secret_key)?;

    // 3. Verify the signature
    EcdsaP256::verify(message, &signature, &public_key)?; // Returns Ok(()) on success

    println!("ECDSA P256 Signature created and verified successfully!");
    Ok(())
}