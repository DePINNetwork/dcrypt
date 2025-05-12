# Digital Signature Schemes (`sign`)

The `sign` crate is dedicated to implementing various digital signature schemes. Digital signatures provide message authenticity (proof of origin), integrity (proof that the message has not been altered), and non-repudiation (the signer cannot deny having signed the message).

This crate aims to provide implementations for both traditional (classical) signature algorithms and post-quantum signature algorithms.

**Note on Current Status:** Many of the signature scheme implementations in the provided codebase snapshot are placeholders or skeletons. They define the necessary structs for keys and signatures and implement the `api::Signature` trait with dummy logic. This documentation describes the intended functionality based on the structure and common practices for these signature schemes.

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

1.  **Ed25519 (`traditional::ed25519`)**
    *   **Description**: EdDSA signature scheme using the Edwards-curve Digital Signature Algorithm with Curve25519. Known for its speed and security.
    *   **Status**: Placeholder implementation (`main.rs`). Constants in `common.rs`.
    *   **Types**: `Ed25519PublicKey`, `Ed25519SecretKey`, `Ed25519Signature`.

2.  **ECDSA (Elliptic Curve Digital Signature Algorithm) (`traditional::ecdsa`)**
    *   **Description**: A widely used signature scheme based on elliptic curve cryptography.
    *   **Variants**:
        *   `EcdsaP256` (using NIST P-256 curve)
        *   `EcdsaP384` (using NIST P-384 curve)
    *   **Status**: Placeholder implementations.
    *   **Types**: `EcdsaP256PublicKey`, etc.

3.  **RSA Signatures (`traditional::rsa`)**
    *   **Description**: Signature schemes based on the RSA public-key cryptosystem.
    *   **Variants**:
        *   `RsaPss` (Probabilistic Signature Scheme - recommended for new applications)
        *   `RsaPkcs1` (Based on PKCS#1 v1.5 padding - widely deployed but PSS is generally preferred)
    *   **Status**: Placeholder implementations.
    *   **Types**: `RsaPublicKey`, `RsaSecretKey`, `RsaSignature`.

4.  **DSA (Digital Signature Algorithm) (`traditional::dsa`)**
    *   **Description**: An older standard for digital signatures based on the discrete logarithm problem in finite fields.
    *   **Status**: Placeholder implementation.
    *   **Types**: `DsaPublicKey`, `DsaSecretKey`, `DsaSignature`.

### Post-Quantum Signature Schemes

1.  **Dilithium (`dilithium`)**
    *   **Description**: A lattice-based signature scheme, chosen by NIST for standardization in the PQC project.
    *   **Variants**: `Dilithium2`, `Dilithium3`, `Dilithium5` (corresponding to NIST security levels 2, 3, and 5).
    *   **Status**: Placeholder implementations. Parameters are in `dcrypt-params`.
    *   **Types**: `DilithiumPublicKey`, `DilithiumSecretKey`, `DilithiumSignature`.
    *   **Files**: `dcrypt_docs/sign/dilithium/README.md`

2.  **Falcon (`falcon`)**
    *   **Description**: A lattice-based signature scheme based on NTRU lattices, also chosen by NIST for standardization. Known for very small signatures and public keys (relative to other PQC schemes).
    *   **Variants**: `Falcon512` (NIST Level 1), `Falcon1024` (NIST Level 5).
    *   **Status**: Placeholder implementations. Parameters are in `dcrypt-params`.
    *   **Types**: `FalconPublicKey`, `FalconSecretKey`, `FalconSignature`.
    *   **Files**: `dcrypt_docs/sign/falcon/README.md`

3.  **SPHINCS+ (`sphincs`)**
    *   **Description**: A stateless hash-based signature scheme, chosen by NIST for standardization. Known for its strong security relying only on the underlying hash function's security, but with larger signatures and slower signing/verification.
    *   **Variants**: `SphincsSha2` (using SHA-256), `SphincsShake` (using SHAKE256). Parameter sets like "-128s", "-128f" would be further specializations.
    *   **Status**: Placeholder implementations. Parameters are in `dcrypt-params`.
    *   **Types**: `SphincsPublicKey`, `SphincsSecretKey`, `SphincsSignature`.
    *   **Files**: `dcrypt_docs/sign/sphincs/README.md`

4.  **Rainbow (`rainbow`)**
    *   **Description**: A multivariate quadratic signature scheme, also chosen by NIST for standardization (though for specific use cases due to large key sizes).
    *   **Variants**: `RainbowI`, `RainbowIII`, `RainbowV`.
    *   **Status**: Placeholder implementations. Parameters are in `dcrypt-params`.
    *   **Types**: `RainbowPublicKey`, `RainbowSecretKey`, `RainbowSignature`.
    *   **Files**: `dcrypt_docs/sign/rainbow/README.md`

## Usage

Once fully implemented, signature schemes would be used as follows (conceptual example using Ed25519):

```rust
// use dcrypt_sign::Ed25519; // Example
// use dcrypt_api::Signature;
// use rand::rngs::OsRng;
// use dcrypt_api::Result;

// fn signature_usage_example() -> Result<()> {
//     let mut rng = OsRng;
//     let message = b"This is a message to be signed.";

//     // 1. Generate key pair
//     let (public_key, secret_key) = Ed25519::keypair(&mut rng)?;

//     // 2. Sign the message
//     let signature = Ed25519::sign(message, &secret_key)?;

//     // 3. Verify the signature
//     Ed25519::verify(message, &signature, &public_key)?; // Returns Ok(()) on success

//     println!("Signature created and verified successfully!");
//     Ok(())
// }
```

This crate aims to offer a robust selection of digital signature algorithms for diverse security requirements, including the transition to post-quantum cryptography.