# Hybrid KEM: EcdhP521 + Kyber1024

## Overview

`EcdhP521Kyber1024` is a high-security hybrid Key Encapsulation Mechanism (KEM) that combines a high-strength classical elliptic curve with a NIST Level 5 post-quantum primitive. This construction provides maximum security against both classical and quantum adversaries, defending against "Harvest Now, Decrypt Later" attacks.

The final shared secret is secure as long as at least one of the underlying algorithms remains unbroken.

## Component Algorithms

1.  **Classical: ECDH P-521 (`secp521r1`)**
    -   An Elliptic Curve Diffie-Hellman scheme using the NIST P-521 curve, offering one of the highest classical security levels available.
    -   It provides strong, standardized security against all known classical attacks.

2.  **Post-Quantum: Kyber-1024**
    -   A lattice-based KEM selected by NIST for standardization, targeting **Security Level 5**.
    -   It is believed to be secure against attacks from future large-scale quantum computers.

## Mechanism

-   **Key Generation**: A hybrid key pair consists of a distinct key pair for both ECDH P-521 and Kyber-1024. The public keys are concatenated.
-   **Encapsulation**: Two separate encapsulation operations are performed, yielding two ciphertexts and two shared secrets.
-   **Key Derivation**: The two shared secrets are combined using **HKDF-SHA256** to produce a single, final 32-byte shared secret.

## Data Sizes

-   **Public Key**: 1635 bytes (`67` from P-521 + `1568` from Kyber-1024)
-   **Ciphertext**: 1635 bytes (`67` from P-521 + `1568` from Kyber-1024)
-   **Shared Secret**: 32 bytes (output of HKDF-SHA256)

## Example Usage

```rust
use dcrypt_api::{Kem, Serialize};
use dcrypt_hybrid::kem::EcdhP521Kyber1024;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Generate a hybrid key pair for the recipient.
    let (public_key, secret_key) = EcdhP521Kyber1024::keypair(&mut rng)?;
    println!("Generated EcdhP521Kyber1024 key pair.");
    println!(" -> Public Key Size: {} bytes", public_key.to_bytes().len());

    // 2. A sender encapsulates a secret using the public key.
    let (ciphertext, sender_shared_secret) = EcdhP521Kyber1024::encapsulate(&mut rng, &public_key)?;
    println!("Encapsulated a shared secret.");
    println!(" -> Ciphertext Size: {} bytes", ciphertext.to_bytes().len());

    // 3. The recipient decapsulates the ciphertext to get the same secret.
    let recipient_shared_secret = EcdhP521Kyber1024::decapsulate(&secret_key, &ciphertext)?;

    // 4. Verify that both parties have the identical 32-byte shared secret.
    assert_eq!(
        *sender_shared_secret.to_bytes_zeroizing(),
        *recipient_shared_secret.to_bytes_zeroizing()
    );
    println!("\nSuccess! Shared secrets match.");

    Ok(())
}