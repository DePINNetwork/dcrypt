# ECDH-KEM with NIST P-521 (`secp521r1`)

This module provides a robust and secure implementation of the Elliptic Curve Diffie-Hellman Key Encapsulation Mechanism (ECDH-KEM) using the **NIST P-521** curve. It offers the highest security level among the standard NIST prime curves.

The implementation conforms to the `dcrypt::api::Kem` trait, ensuring a consistent and predictable API that is interchangeable with other KEMs in the `dcrypt` ecosystem.

## Security Level and Use Cases

`EcdhP521` provides approximately **256 bits of security**, making it suitable for applications with the most stringent security requirements, such as:

-   Protecting top-secret or highly sensitive data.
-   Ensuring very long-term confidentiality, where data must remain secure for decades.
-   Systems where maximum cryptographic strength is required and performance is a secondary consideration.

Given its computational intensity, P-521 is recommended when the performance overhead is acceptable for the level of security achieved.

## Key Characteristics

| Property | Value | Description |
| :--- | :--- | :--- |
| **Curve** | NIST P-521 | A prime-order curve over a 521-bit field. |
| **Security Level** | ~256-bit | The highest classical security level of the NIST curves. |
| **KDF** | HKDF-SHA512 | Uses HKDF with SHA-512 to derive a 64-byte shared secret. |
| **Public Key Size**| 67 bytes | A compressed elliptic curve point (`1` byte prefix + `66` byte coordinate).|
| **Secret Key Size**| 66 bytes | A 521-bit scalar value, padded to 66 bytes. |
| **Ciphertext Size**| 67 bytes | An ephemeral, compressed public key. |
| **Shared Secret** | 64 bytes | The output of the HKDF-SHA512 function. |

## Security Features

This implementation inherits the security-first design principles of the `dcrypt` library:

-   **Strongly-Typed Keys:** Utilizes distinct `EcdhP521PublicKey`, `EcdhP521SecretKey`, and `EcdhP521Ciphertext` structs to prevent accidental misuse of keys from other algorithms.
-   **Secure Key Derivation:** Employs HKDF-SHA512 to derive a strong shared secret from the ECDH exchange. The KDF input binds the ephemeral and static public keys to the final shared secret.
-   **Zeroization on Drop:** Both `EcdhP521SecretKey` and `EcdhP521SharedSecret` are automatically wiped from memory when they go out of scope, minimizing the risk of secret key exposure.
-   **Point Validation:** All public inputs (public keys and ciphertexts) are validated to ensure they are valid points on the P-521 curve and are not the identity point, thwarting invalid curve attacks.
-   **Controlled API:** Access to raw key bytes is restricted to explicit, well-documented methods, preventing common programming errors that could lead to security vulnerabilities.

## Usage Example

Using `EcdhP521` follows the standard `Kem` trait interface.

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::{EcdhP521, EcdhP521PublicKey};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Recipient generates a key pair.
    println!("Generating P-521 key pair (this may take a moment)...");
    let (public_key, secret_key) = EcdhP521::keypair(&mut rng)?;
    println!("Key pair generated.");

    // Serialize for transport.
    let pk_bytes = public_key.to_bytes();

    // 2. Sender encapsulates a shared secret using the public key.
    println!("Encapsulating shared secret...");
    let (ciphertext, shared_secret_sender) = EcdhP521::encapsulate(&mut rng, &public_key)?;
    println!("Encapsulation complete.");

    // 3. Recipient decapsulates the ciphertext to derive the same secret.
    println!("Decapsulating ciphertext...");
    let shared_secret_recipient = EcdhP521::decapsulate(&secret_key, &ciphertext)?;
    println!("Decapsulation complete.");

    // 4. The derived secrets must match.
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_recipient.to_bytes()
    );

    println!("\nSUCCESS: P-521 KEM roundtrip completed successfully!");
    println!("-> Public Key Size:      {} bytes", pk_bytes.len());
    println!("-> Ciphertext Size:      {} bytes", ciphertext.to_bytes().len());
    println!("-> Derived Secret Size:  {} bytes", shared_secret_sender.to_bytes().len());

    Ok(())
}
```

## Performance

Operations on the P-521 curve are significantly more computationally intensive than on smaller curves like P-256. This module includes specific benchmarks to evaluate its performance characteristics.

To run the `EcdhP521` benchmarks:

```bash
cargo bench --bench ecdh_p521
```

This will generate a detailed HTML report in the `target/criterion/` directory, which can be used to assess if P-521 meets the performance requirements of your application.

## License

This crate is licensed under either of the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).