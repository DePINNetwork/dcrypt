# Elliptic Curve Diffie-Hellman KEM

This module provides robust and secure implementations of the Elliptic Curve Diffie-Hellman Key Encapsulation Mechanism (ECDH-KEM) for a variety of standard curves. It is a core component of the `dcrypt` cryptographic library.

All implementations are designed with a security-first mindset, adhering to best practices for cryptographic software development. They provide a unified API by implementing the `dcrypt::api::Kem` trait, making them interchangeable based on security and performance requirements.

## Supported Elliptic Curves

The module includes support for NIST prime curves, a Koblitz curve (used in Bitcoin), and a binary curve, offering a wide range of security levels and performance characteristics.

| Curve Name | Struct Name | Approx. Security | Key Derivation | Point Format |
| :--- | :--- | :--- | :--- | :--- |
| NIST P-192 | `EcdhP192` | ~80-bit | HKDF-SHA256 | Compressed |
| NIST P-224 | `EcdhP224` | ~112-bit | HKDF-SHA256 | Compressed |
| NIST P-256 | `EcdhP256` | ~128-bit | HKDF-SHA256 | Compressed |
| secp256k1 | `EcdhK256` | ~128-bit | HKDF-SHA256 | Compressed |
| sect283k1 | `EcdhB283k` | ~142-bit | HKDF-SHA384 | Compressed |
| NIST P-384 | `EcdhP384` | ~192-bit | HKDF-SHA384 | Compressed |
| NIST P-521 | `EcdhP521` | ~256-bit | HKDF-SHA512 | Compressed |

## Core Design & Security Features

This module prioritizes cryptographic correctness and resilience against common attack vectors.

-   **Type Safety:** Each curve has its own set of distinct, strongly-typed structs for public keys, secret keys, and ciphertexts (e.g., `EcdhP256PublicKey`, `EcdhP384SecretKey`). This prevents accidental mixing of keys from different algorithms at compile time.

-   **Secure Key Derivation:** Shared secrets are derived using a robust Key Derivation Function (HKDF) as recommended by standards like RFC 9180 (HPKE). The KDF input includes the ephemeral public key and the recipient's static public key, binding the shared secret to the entire exchange and preventing unknown key-share attacks.

-   **Memory Safety & Zeroization:** All secret key and shared secret types implement the `ZeroizeOnDrop` trait. This ensures that sensitive cryptographic material is automatically wiped from memory as soon as it goes out of scope, minimizing the window of exposure.

-   **Controlled Data Access:** To prevent accidental leakage or misuse, sensitive types do not implement generic traits like `AsRef<[u8]>`. Access to the underlying bytes is provided only through explicit methods (e.g., `to_bytes()`, `to_bytes_zeroizing()`) that are clearly documented with security warnings.

-   **Point Validation:** All public keys and ciphertexts (which are ephemeral public keys) are rigorously validated upon creation or deserialization. The code checks that the point is on the curve and is not the identity element, protecting against invalid curve and small subgroup attacks.

-   **Bandwidth Efficiency:** All implementations use compressed elliptic curve points for public keys and ciphertexts, significantly reducing their size compared to uncompressed or hybrid formats.

## Usage Example

The `Kem` trait provides a simple, unified interface for all supported curves.

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::{EcdhP256, EcdhP256PublicKey, EcdhP256SecretKey, EcdhP256Ciphertext};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Recipient: Generate a key pair.
    let (pk, sk) = EcdhP256::keypair(&mut rng)?;

    // Serialize the public key to send to others.
    let pk_bytes = pk.to_bytes();

    // 2. Sender: Restore the public key and encapsulate.
    let recipient_pk = EcdhP256PublicKey::from_bytes(&pk_bytes)?;
    let (ciphertext, shared_secret_sender) = EcdhP256::encapsulate(&mut rng, &recipient_pk)?;

    // 3. Recipient: Decapsulate the ciphertext with the secret key.
    let shared_secret_recipient = EcdhP256::decapsulate(&sk, &ciphertext)?;

    // 4. Verification: The derived secrets must match.
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_recipient.to_bytes()
    );

    println!("ECDH-P256 KEM roundtrip successful!");
    println!("Public Key Size: {} bytes", pk_bytes.len());
    println!("Ciphertext Size: {} bytes", ciphertext.to_bytes().len());
    println!("Shared Secret Size: {} bytes", shared_secret_sender.to_bytes().len());

    Ok(())
}
```

## Benchmarks

Performance is a critical aspect of cryptographic algorithm selection. This module is accompanied by a comprehensive benchmark suite that measures the performance of key generation, encapsulation, and decapsulation for every supported curve.

To run the benchmarks:

```bash
# Run all ECDH benchmarks
cargo bench --bench 'ecdh_*'

# Run a specific comparison suite
cargo bench --bench ecdh_comparison
```

The results are generated in the `target/criterion/` directory and provide detailed HTML reports, allowing you to choose the best curve for your application's performance and security needs.

## License

This crate is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).