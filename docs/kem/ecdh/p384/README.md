# ECDH-KEM with NIST P-384 (`secp384r1`)

This module provides a secure implementation of the Elliptic Curve Diffie-Hellman Key Encapsulation Mechanism (ECDH-KEM) using the **NIST P-384** curve (also known as `secp384r1`). It is part of the `dcrypt::kem::ecdh` module and offers a high level of security suitable for long-term data protection.

The implementation conforms to the `dcrypt::api::Kem` trait, ensuring a consistent and predictable interface that aligns with other KEMs in the `dcrypt` library.

## Security Characteristics

The P-384 implementation is built with a strong focus on cryptographic best practices, providing approximately **192 bits of security**.

-   **Key Derivation Function (KDF):** It uses **HKDF-SHA384** to derive the final shared secret. The choice of SHA-384 aligns with the security level of the P-384 curve itself, producing a robust 48-byte shared secret. The KDF input is constructed from the shared elliptic curve point's x-coordinate, the ephemeral public key, and the recipient's static public key to prevent key-compromise impersonation.

-   **Strongly-Typed Data:** The module exposes distinct types to prevent misuse:
    -   `EcdhP384PublicKey`: A validated P-384 public key.
    -   `EcdhP384SecretKey`: A P-384 scalar value that is zeroized on drop.
    -   `EcdhP384Ciphertext`: An ephemeral P-384 public key used for transport.
    -   `EcdhP384SharedSecret`: The derived secret, also zeroized on drop.

-   **Data Format & Efficiency:** Public keys and ciphertexts use **compressed point format**, reducing their on-the-wire size to just 49 bytes.

-   **Mandatory Validation:** All public keys (static and ephemeral) are validated to ensure they are valid points on the P-384 curve and are not the point at infinity. This protects against invalid curve attacks.

-   **Secure Memory Handling:** `EcdhP384SecretKey` and `EcdhP384SharedSecret` wrappers ensure that sensitive data is securely wiped from memory when it is no longer in use.

## Data Structures and Sizes

| Component | Struct | Serialized Size (Bytes) | Description |
| :--- | :--- | :--- | :--- |
| **Public Key** | `EcdhP384PublicKey` | 49 | A compressed P-384 point. |
| **Secret Key** | `EcdhP384SecretKey` | 48 | A 384-bit scalar. |
| **Ciphertext** | `EcdhP384Ciphertext`| 49 | An ephemeral, compressed P-384 public key. |
| **Shared Secret**| `EcdhP384SharedSecret`| 48 | The output of the HKDF-SHA384 function. |

## Usage Example

The interface follows the standard `Kem` trait.

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::EcdhP384;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Recipient generates a key pair for P-384.
    println!("Generating P-384 key pair...");
    let (public_key, secret_key) = EcdhP384::keypair(&mut rng)?;

    // 2. Sender encapsulates a secret using the recipient's public key.
    println!("Encapsulating a shared secret...");
    let (ciphertext, shared_secret_sender) = EcdhP384::encapsulate(&mut rng, &public_key)?;

    // 3. Recipient decapsulates the ciphertext to derive the same secret.
    println!("Decapsulating the ciphertext...");
    let shared_secret_recipient = EcdhP384::decapsulate(&secret_key, &ciphertext)?;

    // 4. The derived secrets must be identical.
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_recipient.to_bytes()
    );

    println!("\nSuccess! ECDH-P384 roundtrip complete.");
    println!("-> Public Key Size:   {} bytes", public_key.to_bytes().len());
    println!("-> Secret Key Size:   {} bytes", secret_key.to_bytes().len());
    println!("-> Ciphertext Size:   {} bytes", ciphertext.to_bytes().len());
    println!("-> Shared Secret Size: {} bytes", shared_secret_sender.to_bytes().len());

    Ok(())
}
```

## Benchmarks

Specific performance benchmarks are provided for the P-384 implementation to evaluate its speed for key generation, encapsulation, and decapsulation.

To run the dedicated P-384 benchmark suite, use the following command:

```bash
cargo bench --bench ecdh_p384
```

The results will be available in the `target/criterion/` directory.

## License

This crate is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).