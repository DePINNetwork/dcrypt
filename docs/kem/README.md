# Key Encapsulation Mechanisms (`kem`)

The `kem` crate is responsible for implementing various Key Encapsulation Mechanisms (KEMs). KEMs are cryptographic schemes used to securely establish shared secrets between parties, typically involving a public-key component. One party (sender) uses the recipient's public key to generate a shared secret and an "encapsulation" (ciphertext) of that secret. The recipient then uses their private key to "decapsulate" the ciphertext and recover the same shared secret.

This crate provides implementations for both traditional (classical) KEMs and post-quantum KEMs.

**Note on Current Status:** Many of the KEM implementations in the provided codebase snapshot are placeholders or skeletons. They define the necessary structs and implement the `api::Kem` trait with dummy logic, indicating the intended structure rather than full cryptographic functionality. The documentation below reflects this by outlining the intended algorithm and its structure.

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
    *   **Variants**:
        *   `RsaKem2048` (using 2048-bit modulus)
        *   `RsaKem4096` (using 4096-bit modulus, noted as similar implementation to 2048)
    *   **Files**: `dcrypt_docs/kem/rsa/README.md` (covers `common.rs`, `rsa2048.rs`, `rsa4096.rs`)
    *   **Status**: Placeholder implementations.

2.  **Diffie-Hellman KEM (`dh`)**
    *   **Description**: KEM based on the Diffie-Hellman key exchange protocol over finite fields (MODP groups).
    *   **Variants**:
        *   `Dh2048` (using a 2048-bit modulus, likely RFC 3526 Group 14)
    *   **Files**: `dcrypt_docs/kem/dh/README.md`
    *   **Status**: Placeholder implementation.

3.  **ECDH-KEM (Elliptic Curve Diffie-Hellman KEM) (`ecdh`)**
    *   **Description**: KEM based on Diffie-Hellman key exchange over elliptic curves.
    *   **Variants**:
        *   `EcdhP256` (using NIST P-256 curve)
        *   `EcdhP384` (using NIST P-384 curve)
    *   **Files**: `dcrypt_docs/kem/ecdh/README.md`
    *   **Status**: Placeholder implementations.

### Post-Quantum KEMs

1.  **Kyber (`kyber`)**
    *   **Description**: A lattice-based KEM chosen by NIST for standardization in the PQC project.
    *   **Variants**:
        *   `Kyber512` (NIST Security Level 1)
        *   `Kyber768` (NIST Security Level 3)
        *   `Kyber1024` (NIST Security Level 5)
    *   **Files**: `dcrypt_docs/kem/kyber/README.md` (covers `common.rs`, `kyber512.rs`, etc.)
    *   **Status**: Placeholder implementations. Parameters are defined in `dcrypt-params`.

2.  **NTRU (`ntru`)**
    *   **Description**: A lattice-based KEM. The snapshot includes NTRU-HPS (likely NTRUEncrypt) and NTRU-EES.
    *   **Variants**:
        *   `NtruHps` (e.g., NTRU-HPS-2048-509)
        *   `NtruEes` (e.g., NTRU-HRSS-701, often referred to as NTRUEncrypt parameters)
    *   **Files**: `dcrypt_docs/kem/ntru/README.md`
    *   **Status**: Placeholder implementations. Parameters are defined in `dcrypt-params`.

3.  **SABER (`saber`)**
    *   **Description**: A lattice-based KEM, another finalist in the NIST PQC standardization process.
    *   **Variants**:
        *   `LightSaber`
        *   `Saber`
        *   `FireSaber`
    *   **Files**: `dcrypt_docs/kem/saber/README.md`
    *   **Status**: Placeholder implementations. Parameters are defined in `dcrypt-params`.

4.  **McEliece (`mceliece`)**
    *   **Description**: A code-based KEM, one of the oldest PQC schemes, also selected by NIST for standardization. Known for large public keys.
    *   **Variants**:
        *   `McEliece348864` (NIST Security Level 1, for variant `mceliece348864`)
        *   `McEliece6960119` (NIST Security Level 5, for variant `mceliece6960119`)
    *   **Files**: `dcrypt_docs/kem/mceliece/README.md`
    *   **Status**: Placeholder implementations. Parameters are defined in `dcrypt-params`.

## Error Handling

The `kem` crate defines its own `Error` enum (`dcrypt_docs/kem/error/README.md`) for KEM-specific errors (e.g., `KeyGeneration`, `Encapsulation`, `Decapsulation`, `InvalidKey`, `InvalidCiphertext`). These errors can be converted from `algorithms::Error` and into `api::Error`. Validation utilities specific to KEMs are also provided.

## Usage

Once fully implemented, KEMs would be used as follows (conceptual example):

```rust
// use dcrypt_kem::kyber::Kyber768; // Example
// use dcrypt_api::Kem;
// use rand::rngs::OsRng;
// use dcrypt_api::Result;

// fn kem_usage_example() -> Result<()> {
//     let mut rng = OsRng;

//     // 1. Generate recipient's key pair
//     let (public_key, secret_key) = Kyber768::keypair(&mut rng)?;

//     // 2. Sender encapsulates a shared secret using recipient's public key
//     let (ciphertext, shared_secret_sender) = Kyber768::encapsulate(&mut rng, &public_key)?;

//     // 3. Recipient decapsulates the ciphertext using their secret key
//     let shared_secret_receiver = Kyber768::decapsulate(&secret_key, &ciphertext)?;

//     // Both parties now have the same shared secret
//     assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref());

//     println!("KEM operation successful. Shared secret established.");
//     Ok(())
// }
```

This crate aims to provide a comprehensive suite of KEMs for various security needs, paving the way for hybrid cryptographic solutions by combining these with traditional schemes.