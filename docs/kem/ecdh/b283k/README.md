# ECDH-KEM with `sect283k1`

This module provides a Key Encapsulation Mechanism (KEM) based on the Elliptic Curve Diffie-Hellman (ECDH) protocol over the SECG binary curve `sect283k1`. This curve is also referred to as `B-283k`.

As a component of the `dcrypt` cryptographic library, this implementation adheres to the `dcrypt::api::Kem` trait, ensuring a consistent and secure interface. It is designed for applications requiring a security level of approximately 142 bits.

## Curve Characteristics

The `sect283k1` curve has distinct properties compared to the more common NIST prime curves.

| Property | Value | Description |
| :--- | :--- | :--- |
| **Curve Type** | Koblitz Binary Curve | Operations are performed over the finite field GF(2^283). |
| **Security Strength**| ~142 bits | Offers a security level between P-256 (~128-bit) and P-384 (~192-bit). |
| **Key Derivation** | HKDF-SHA384 | Uses the robust HKDF with SHA-384 to derive a 48-byte shared secret. |
| **Public Key Size** | **37 bytes** | A compressed point representation (`1` byte prefix + `36` byte x-coordinate). |
| **Secret Key Size** | **36 bytes** | The size of the scalar multiplier. |
| **Ciphertext Size** | **37 bytes** | The ephemeral public key, also in compressed format. |
| **Shared Secret Size**| **48 bytes** | The output size of the HKDF-SHA384 function. |

## Security Features

This implementation inherits the security-first design principles of the `dcrypt` library:

-   **Strongly-Typed Keys:** Employs distinct types for keys and ciphertexts (`EcdhB283kPublicKey`, `EcdhB283kSecretKey`, `EcdhB283kCiphertext`) to prevent logical errors and misuse at the type level.

-   **Robust Key Derivation:** The shared secret is derived using HKDF-SHA384, binding it to both the sender's ephemeral key and the recipient's static key. This protects against key-reuse and unknown key-share attacks.

-   **Automatic Zeroization:** Secret key and shared secret materials are held in special wrappers that implement `ZeroizeOnDrop`. This ensures sensitive data is securely erased from memory as soon as it is no longer needed.

-   **Strict Point Validation:** All public inputs (public keys and ciphertexts) are rigorously validated to ensure they represent valid points on the `sect283k1` curve and are not the point-at-infinity. This is a critical defense against invalid curve attacks.

-   **No Direct Byte Access:** To prevent tampering and accidental leakage, sensitive key types do not expose their raw bytes through generic traits like `AsRef`. Access is restricted to explicit, security-conscious methods like `to_bytes()`.

## Performance Considerations

Binary curve cryptography, like that used in `sect283k1`, can exhibit different performance characteristics than prime curve cryptography on general-purpose CPUs. In many software-only implementations, binary curve operations may be slower.

Users should evaluate the performance in their specific target environment. The crate provides dedicated benchmarks to measure and compare its performance against other curves.

## Usage Example

The module follows the standard `Kem` trait interface, making it simple to use.

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::b283k::{EcdhB283k, EcdhB283kPublicKey};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Recipient generates a key pair.
    let (public_key, secret_key) = EcdhB283k::keypair(&mut rng)?;

    // Serialize the public key for distribution.
    let pk_bytes = public_key.to_bytes();
    assert_eq!(pk_bytes.len(), 37); // 1 + 36 bytes

    // 2. Sender encapsulates a secret using the public key.
    let restored_pk = EcdhB283kPublicKey::from_bytes(&pk_bytes)?;
    let (ciphertext, shared_secret_sender) = EcdhB283k::encapsulate(&mut rng, &restored_pk)?;
    assert_eq!(ciphertext.to_bytes().len(), 37);

    // 3. Recipient decapsulates the ciphertext to get the same secret.
    let shared_secret_recipient = EcdhB283k::decapsulate(&secret_key, &ciphertext)?;

    // 4. Verify the secrets match.
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_recipient.to_bytes()
    );
    assert_eq!(shared_secret_sender.to_bytes().len(), 48); // HKDF-SHA384 output

    println!("ECDH-B283k KEM roundtrip successful!");
    println!("Public Key Size: {} bytes", pk_bytes.len());
    println!("Ciphertext Size: {} bytes", ciphertext.to_bytes().len());
    println!("Shared Secret Size: {} bytes", shared_secret_sender.to_bytes().len());

    Ok(())
}
```

## Testing & Benchmarking

The correctness and security of this implementation are verified by the tests in `src/ecdh/b283k/tests.rs`.

Performance can be measured by running the dedicated benchmark suite:

```bash
cargo bench --bench ecdh_b283k
```

The results, which include key generation, encapsulation, and decapsulation timings, will be available in the `target/criterion/` directory.

## License

This crate is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).