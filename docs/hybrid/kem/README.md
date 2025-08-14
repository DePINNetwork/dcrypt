# Hybrid Key Encapsulation Mechanisms (KEM)

## Overview

This module provides hybrid Key Encapsulation Mechanisms (KEMs) designed to secure data against threats from both classical and quantum computers. By combining a classical, battle-tested algorithm with a forward-looking post-quantum algorithm, this module offers a robust defense against "Harvest Now, Decrypt Later" attacks.

The core principle is **crypto-agility**: the final shared secret is secure as long as at least one of the underlying cryptographic primitives remains unbroken.

### Design

The implementation follows a modern, extensible design. A generic `HybridKemEngine` encapsulates the core hybrid logic (key generation, encapsulation, and decapsulation). For each specific combination of algorithms, a concrete, lightweight struct is provided (e.g., `EcdhP256Kyber768`). This approach offers several advantages:
-   **Type Safety**: Each hybrid scheme is a distinct type, preventing accidental misuse.
-   **Extensibility**: Adding new combinations (e.g., different curves or PQ algorithms) is trivial and does not require duplicating logic.
-   **Maintainability**: The core hybrid logic is centralized in one place.

---

## Available Hybrid KEMs

This module currently provides the following NIST-recommended combinations:

### 1. `EcdhP256Kyber768`

This is a hybrid KEM that combines two well-regarded algorithms for robust security:
*   **Classical KEM**: Elliptic Curve Diffie-Hellman (ECDH) using the NIST P-256 curve (`secp256r1`).
*   **Post-Quantum KEM**: `Kyber-768` (NIST Security Level 3), selected by NIST for standardization.

### 2. `EcdhP384Kyber1024`

This scheme offers a higher security level by combining:
*   **Classical KEM**: Elliptic Curve Diffie-Hellman (ECDH) using the NIST P-384 curve (`secp384r1`).
*   **Post-Quantum KEM**: `Kyber-1024` (NIST Security Level 5).

### How It Works

1.  **Key Generation**: A hybrid key pair contains a distinct key pair for both the classical and post-quantum schemes. The public keys are concatenated to form the `HybridPublicKey`.
2.  **Encapsulation**: Two independent encapsulation operations are performed, yielding two ciphertexts and two shared secrets. The ciphertexts are concatenated into a single `HybridCiphertext`.
3.  **Key Derivation**: The two shared secrets are combined using **HKDF-SHA256** with a domain separation tag (`depin-hybrid-kem-v1`) to produce a single, 32-byte final shared secret.
4.  **Decapsulation**: The recipient performs two decapsulations and applies the same HKDF construction to derive the identical final shared secret.

---

## Example Usage

### Example 1: `EcdhP256Kyber768`

```rust
use dcrypt::api::{Kem, Serialize};
use dcrypt::hybrid::kem::EcdhP256Kyber768;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. RECIPIENT: Generate a hybrid key pair.
    let (public_key, secret_key) = EcdhP256Kyber768::keypair(&mut rng)?;
    println!("EcdhP256Kyber768 keys generated.");
    println!("Public key size: {} bytes", public_key.to_bytes().len());

    // 2. SENDER: Encapsulate a shared secret.
    let (ciphertext, sender_ss) = EcdhP256Kyber768::encapsulate(&mut rng, &public_key)?;
    println!("Ciphertext size: {} bytes", ciphertext.to_bytes().len());

    // 3. RECIPIENT: Decapsulate the ciphertext.
    let recipient_ss = EcdhP256Kyber768::decapsulate(&secret_key, &ciphertext)?;

    // 4. VERIFICATION: Both parties now have the identical 32-byte shared secret.
    assert_eq!(*sender_ss.to_bytes_zeroizing(), *recipient_ss.to_bytes_zeroizing());
    println!("Success! EcdhP256Kyber768 shared secrets match.");

    Ok(())
}
```

### Example 2: `EcdhP384Kyber1024`

```rust
use dcrypt::api::{Kem, Serialize};
use dcrypt::hybrid::kem::EcdhP384Kyber1024;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Generate the higher-security key pair.
    let (public_key, secret_key) = EcdhP384Kyber1024::keypair(&mut rng)?;
    println!("\nEcdhP384Kyber1024 keys generated.");
    println!("Public key size: {} bytes", public_key.to_bytes().len());

    // 2. Encapsulate a shared secret.
    let (ciphertext, sender_ss) = EcdhP384Kyber1024::encapsulate(&mut rng, &public_key)?;
    println!("Ciphertext size: {} bytes", ciphertext.to_bytes().len());

    // 3. Decapsulate the ciphertext.
    let recipient_ss = EcdhP384Kyber1024::decapsulate(&secret_key, &ciphertext)?;

    // 4. Verify the secrets match.
    assert_eq!(*sender_ss.to_bytes_zeroizing(), *recipient_ss.to_bytes_zeroizing());
    println!("Success! EcdhP384Kyber1024 shared secrets match.");

    Ok(())
}
```