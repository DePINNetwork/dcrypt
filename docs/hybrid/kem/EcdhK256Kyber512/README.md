# Hybrid KEM: EcdhK256 + Kyber512

## Overview

`EcdhK256Kyber512` is a hybrid Key Encapsulation Mechanism (KEM) that combines a classical Koblitz curve with a post-quantum lattice-based primitive. This construction is particularly relevant for systems migrating from `secp256k1`-based cryptography (common in blockchains) and provides robust security against both classical and quantum adversaries.

The final shared secret is secure as long as at least one of the underlying algorithms remains unbroken.

## Component Algorithms

1.  **Classical: ECDH K-256 (`secp256k1`)**
    -   An Elliptic Curve Diffie-Hellman scheme using the Koblitz curve `secp256k1`, widely used in cryptocurrencies like Bitcoin and Ethereum.
    -   It provides strong, standardized security against all known classical attacks.

2.  **Post-Quantum: Kyber-512**
    -   A lattice-based KEM selected by NIST for standardization, targeting **Security Level 1**.
    -   It is believed to be secure against attacks from future large-scale quantum computers.

## Mechanism

-   **Key Generation**: A hybrid key pair consists of a distinct key pair for both ECDH K-256 and Kyber-512. The public keys are concatenated.
-   **Encapsulation**: Two separate encapsulation operations are performed, yielding two ciphertexts and two shared secrets.
-   **Key Derivation**: The two shared secrets are combined using **HKDF-SHA256** to produce a single, final 32-byte shared secret.

## Data Sizes

-   **Public Key**: 833 bytes (`33` from K-256 + `800` from Kyber-512)
-   **Ciphertext**: 801 bytes (`33` from K-256 + `768` from Kyber-512)
-   **Shared Secret**: 32 bytes (output of HKDF-SHA256)

## Example Usage

```rust
use dcrypt_api::{Kem, Serialize};
use dcrypt_hybrid::kem::EcdhK256Kyber512;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Generate a hybrid key pair for the recipient.
    let (public_key, secret_key) = EcdhK256Kyber512::keypair(&mut rng)?;
    println!("Generated EcdhK256Kyber512 key pair.");
    println!(" -> Public Key Size: {} bytes", public_key.to_bytes().len());

    // 2. A sender encapsulates a secret using the public key.
    let (ciphertext, sender_shared_secret) = EcdhK256Kyber512::encapsulate(&mut rng, &public_key)?;
    println!("Encapsulated a shared secret.");
    println!(" -> Ciphertext Size: {} bytes", ciphertext.to_bytes().len());

    // 3. The recipient decapsulates the ciphertext to get the same secret.
    let recipient_shared_secret = EcdhK256Kyber512::decapsulate(&secret_key, &ciphertext)?;

    // 4. Verify that both parties have the identical 32-byte shared secret.
    assert_eq!(
        *sender_shared_secret.to_bytes_zeroizing(),
        *recipient_shared_secret.to_bytes_zeroizing()
    );
    println!("\nSuccess! Shared secrets match.");

    Ok(())
}