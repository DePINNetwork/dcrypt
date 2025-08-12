# ECDH-KEM with `secp256k1`

This module provides a robust and secure implementation of the Elliptic Curve Diffie-Hellman Key Encapsulation Mechanism (ECDH-KEM) using the `secp256k1` curve, commonly referred to as K-256.

The `secp256k1` curve is widely known for its use in cryptocurrencies such as Bitcoin and Ethereum. This implementation offers approximately 128 bits of security and adheres to the high standards of the `dcrypt` cryptographic library.

## Module Design and Security

The `EcdhK256` implementation is built with a focus on cryptographic best practices and resilience against common attacks.

-   **Unified API:** Implements the `dcrypt::api::Kem` trait, ensuring a consistent and predictable interface that is interchangeable with other KEMs in the library.
-   **Type Safety:** Provides distinct, strongly-typed structs (`EcdhK256PublicKey`, `EcdhK256SecretKey`, `EcdhK256Ciphertext`, `EcdhK256SharedSecret`) to prevent the misuse or accidental mixing of cryptographic keys.
-   **Secure Key Derivation:** The shared secret is derived using **HKDF-SHA256**. The Key Derivation Function's input is constructed from the shared point's x-coordinate, the ephemeral public key, and the recipient's public key. This binds the resulting secret to the entire context of the exchange, protecting against key-share attacks.
-   **Point Validation:** All public keys (both static and ephemeral) are rigorously validated to ensure they are valid points on the `secp256k1` curve and are not the identity element, mitigating invalid-curve and small-subgroup attacks.
-   **Memory Security:** Secret key (`EcdhK256SecretKey`) and shared secret (`EcdhK256SharedSecret`) types implement `ZeroizeOnDrop`, ensuring their contents are automatically wiped from memory when they are no longer in use.
-   **Controlled Data Access:** To prevent accidental exposure, direct byte access via traits like `AsRef<[u8]>` is intentionally avoided for sensitive types. Serialization must be performed using explicit methods like `to_bytes()` and `to_bytes_zeroizing()`.
-   **Bandwidth Efficiency:** Uses the 33-byte compressed point format for all public keys and ciphertexts to minimize data transmission size.

## Data Sizes

| Item | Size (bytes) | Description |
| :--- | :--- | :--- |
| **Public Key** | 33 | A compressed `secp256k1` point. |
| **Secret Key** | 32 | A 256-bit scalar. |
| **Ciphertext** | 33 | An ephemeral, compressed `secp256k1` point. |
| **Shared Secret** | 32 | The output of the HKDF-SHA256 KDF. |

## Usage Example

Using `EcdhK256` follows the standard `Kem` trait pattern.

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::k256::{EcdhK256, EcdhK256PublicKey};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Recipient generates a key pair.
    let (public_key, secret_key) = EcdhK256::keypair(&mut rng)?;

    // The recipient can serialize and share their public key.
    let pk_bytes = public_key.to_bytes();

    // 2. Sender restores the public key from bytes to encapsulate a secret.
    // The `from_bytes` method validates the key material.
    let recipient_pk = EcdhK256PublicKey::from_bytes(&pk_bytes)?;
    let (ciphertext, shared_secret_sender) = EcdhK256::encapsulate(&mut rng, &recipient_pk)?;

    // 3. Recipient uses their secret key to decapsulate the ciphertext.
    let shared_secret_recipient = EcdhK256::decapsulate(&secret_key, &ciphertext)?;

    // 4. Both parties now have the identical shared secret.
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_recipient.to_bytes()
    );

    println!("ECDH-K256 (secp256k1) KEM roundtrip successful!");
    println!("Shared Secret: ... (32 bytes)");

    // The `Zeroize` trait ensures secret data is wiped from memory.
    // `to_bytes()` on secret types returns a `Zeroizing<Vec<u8>>` wrapper.
    let mut secret_bytes = secret_key.to_bytes();
    // `secret_bytes` is automatically zeroized when it goes out of scope.

    Ok(())
}
```

## Performance

While `secp256k1` is secure, its operations may be slower than the NIST prime-field curves (like P-256) on platforms that lack specialized hardware instructions for Koblitz curves. For detailed performance metrics, you can run the dedicated benchmark suite for this module:

```bash
cargo bench --bench ecdh_k256
```

To compare its performance against other curves, run the comparison suite:

```bash
cargo bench --bench ecdh_comparison
```

## License

This module is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).