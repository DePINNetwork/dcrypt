# Hybrid Key Encapsulation Mechanisms (KEM)

## Overview

This module provides hybrid Key Encapsulation Mechanisms (KEMs) designed to secure data against threats from both classical and quantum computers. By combining a classical, battle-tested algorithm with a forward-looking post-quantum algorithm, this module offers a robust defense against "Harvest Now, Decrypt Later" attacks, where encrypted data is stored today to be decrypted in the future by a powerful quantum computer.

The core principle is **crypto-agility**: creating a system where the security relies on the strengths of two different cryptographic families. The resulting shared secret is secure as long as at least one of the underlying cryptographic primitives remains unbroken. [6, 7]

The primary implementation in this module is `EcdhKyber768`. [1]

---

## Hybrid KEM: `EcdhKyber768`

`EcdhKyber768` is a hybrid KEM that creates a secure shared secret by combining two well-regarded algorithms:

1.  **Classical KEM: ECDH on P-256**
    *   **Algorithm**: Elliptic Curve Diffie-Hellman (ECDH) using the NIST P-256 curve (also known as `secp256r1`).
    *   **Security**: Provides strong security against all known classical computing attacks. It is a widely deployed and trusted standard for key exchange.

2.  **Post-Quantum KEM: Kyber-768**
    *   **Algorithm**: CRYSTALS-Kyber at NIST Security Level 3.
    *   **Security**: Selected by the U.S. National Institute of Standards and Technology (NIST) as the primary KEM for standardization in its Post-Quantum Cryptography (PQC) project. It is believed to be secure against attacks from future large-scale quantum computers.

### How It Works

The hybrid construction ensures that a compromise of only one of the algorithms does not compromise the final shared secret.

1.  **Key Generation**: A hybrid key pair is created by generating a distinct key pair for both ECDH P-256 and Kyber-768. The public and secret keys from both schemes are stored together in `HybridPublicKey` and `HybridSecretKey` structs, respectively.
2.  **Encapsulation (Creating a Shared Secret)**:
    *   The sender takes the recipient's hybrid public key.
    *   Two independent encapsulation operations are performed: one for ECDH and one for Kyber. This yields two separate ciphertexts and two separate shared secrets.
    *   The two ciphertexts are concatenated into a single `HybridCiphertext`.
    *   The two shared secrets are combined using a **HKDF-SHA256** function. This Key Derivation Function hashes the concatenated secrets to produce a single, cryptographically strong final shared secret of 32 bytes.
3.  **Decapsulation (Deriving the Shared Secret)**:
    *   The recipient uses their hybrid secret key and the received `HybridCiphertext`.
    *   The hybrid ciphertext is split, and each part is decapsulated by its corresponding algorithm (ECDH and Kyber).
    *   This also yields two shared secrets.
    *   The recipient applies the exact same **HKDF-SHA256** function to the two secrets to derive the identical final shared secret.

### Data Structures

-   `HybridPublicKey`: A struct containing an `EcdhP256PublicKey` and a `KyberPublicKey`. The serialized format is a simple concatenation of the two keys.
-   `HybridSecretKey`: A struct containing an `EcdhP256SecretKey` and a `KyberSecretKey`. This struct implements `ZeroizeOnDrop` to securely erase the key material from memory when it goes out of scope.
-   `HybridCiphertext`: A struct containing an `EcdhP256Ciphertext` and a `KyberCiphertext`, also serialized via concatenation.

---

## Example Usage

The following example demonstrates a full roundtrip: key generation, encapsulation by a sender, and decapsulation by the recipient.

```rust
// This example assumes a top-level `dcrypt` crate that re-exports modules
// from its workspace crates, which is a common pattern.
use dcrypt::api::Kem;
use dcrypt::hybrid::kem::EcdhKyber768;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. RECIPIENT: Generate a hybrid key pair.
    // This creates both an ECDH P-256 key pair and a Kyber-768 key pair.
    let (public_key, secret_key) = EcdhKyber768::keypair(&mut rng)?;
    println!("Hybrid public and secret keys generated.");

    // The public key can now be serialized and shared with the sender.
    let public_key_bytes = public_key.to_bytes();
    println!("Public key size: {} bytes", public_key_bytes.len());


    // 2. SENDER: Encapsulate a shared secret for the recipient's public key.
    // This step generates a secret and encrypts it for both ECDH and Kyber.
    let (ciphertext, sender_shared_secret) =
        EcdhKyber768::encapsulate(&mut rng, &public_key)?;
    println!("Encapsulation successful.");

    // The ciphertext is sent to the recipient.
    let ciphertext_bytes = ciphertext.to_bytes();
    println!("Ciphertext size: {} bytes", ciphertext_bytes.len());


    // 3. RECIPIENT: Decapsulate the ciphertext using their secret key.
    // This uses both the ECDH and Kyber secret keys to derive the same shared secret.
    let recipient_shared_secret =
        EcdhKyber768::decapsulate(&secret_key, &ciphertext)?;
    println!("Decapsulation successful.");


    // 4. VERIFICATION: Both parties now possess the identical 32-byte shared secret.
    assert_eq!(
        &*sender_shared_secret.to_bytes_zeroizing(),
        &*recipient_shared_secret.to_bytes_zeroizing()
    );
    assert_eq!(sender_shared_secret.len(), 32);

    println!("\nSuccess! The derived shared secrets match.");
    println!("Sender's secret:   {:x?}", &*sender_shared_secret.to_bytes_zeroizing());
    println!("Recipient's secret: {:x?}", &*recipient_shared_secret.to_bytes_zeroizing());

    Ok(())
}