# ECDH-KEM with NIST P-224 (`secp224r1`)

This module provides a robust and secure implementation of the Elliptic Curve Diffie-Hellman Key Encapsulation Mechanism (ECDH-KEM) using the NIST P-224 curve (`secp224r1`).

A key feature of this implementation is the inclusion of an **authentication tag** with the ciphertext. This provides key confirmation and protects against certain active attacks, making it a more resilient choice than basic, unauthenticated ECDH.

This module is part of the `dcrypt::kem` crate and implements the `dcrypt::api::Kem` trait.

## Specification Summary

| Property | Value | Description |
| :--- | :--- | :--- |
| **Curve** | NIST P-224 | Also known as `secp224r1`. |
| **Security Level** | ~112 bits | Provides a medium level of security. |
| **Key Derivation** | HKDF-SHA256 | Uses a robust KDF for deriving the shared secret. |
| **Authentication**| **HMAC-SHA256** | A 16-byte tag is appended to the ciphertext for authentication. |
| **Public Key Size** | 29 bytes | A compressed elliptic curve point. |
| **Secret Key Size** | 28 bytes | The scalar value. |
| **Ciphertext Size**| **45 bytes** | 29-byte compressed point + 16-byte authentication tag. |
| **Shared Secret Size**| 32 bytes | The output of the KDF. |

## Key Feature: Authenticated KEM

Unlike many standard KEM constructions, this `EcdhP224` implementation produces an **authenticated ciphertext**. This provides two critical security benefits:

1.  **Key Confirmation:** The authentication tag is derived from the shared secret itself. When a recipient successfully verifies the tag during decapsulation, they have cryptographic proof that the sender computed the exact same shared secret.

2.  **Ciphertext Integrity:** The tag protects the ephemeral public key from being modified in transit. If an attacker tampers with the ciphertext, the tag verification will fail, and the decapsulation process will return an error. This prevents ciphertext substitution attacks.

Because of this feature, an attempt to decapsulate with the wrong secret key or a corrupted ciphertext will result in a hard failure (`Err(DecryptionFailed)`), rather than succeeding and producing an incorrect shared secret.

## Security Design

This implementation adheres to the high security standards of the `dcrypt` library:

-   **Type Safety:** Uses distinct structs (`EcdhP224PublicKey`, `EcdhP224SecretKey`, `EcdhP224Ciphertext`) to prevent the misuse or accidental mixing of cryptographic keys.
-   **Constant-Time Operations:** The critical authentication tag comparison is performed in constant time using the `SecureCompare` trait to prevent timing-based side-channel attacks.
-   **Automatic Zeroization:** All sensitive data, including the secret key and derived shared secret, is held in buffers that are automatically and securely zeroed from memory when they are no longer in use (`ZeroizeOnDrop`).
-   **Mandatory Validation:** All incoming public keys and ciphertexts are validated to ensure they represent valid points on the P-224 curve and are not the identity point, mitigating invalid-curve attacks.
-   **Controlled API:** Direct byte access to sensitive key material is intentionally restricted. Explicit serialization methods (`to_bytes()`, `to_bytes_zeroizing()`) must be used, ensuring developers are aware when they are handling raw key data.

## Usage Example

The module follows the standard `Kem` trait, ensuring a consistent and predictable developer experience.

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::{EcdhP224, EcdhP224PublicKey, EcdhP224SecretKey, EcdhP224Ciphertext};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. A recipient generates a key pair.
    let (public_key, secret_key) = EcdhP224::keypair(&mut rng)?;

    // 2. A sender uses the recipient's public key to encapsulate.
    // The result is the authenticated ciphertext and the shared secret.
    let (ciphertext, shared_secret_sender) = EcdhP224::encapsulate(&mut rng, &public_key)?;

    // The ciphertext (45 bytes) is sent to the recipient.
    let ct_bytes = ciphertext.to_bytes();

    // --- Network Transmission ---

    // 3. The recipient receives the ciphertext and decapsulates it.
    // This step includes verifying the authentication tag.
    let shared_secret_recipient = EcdhP224::decapsulate(&secret_key, &ciphertext)?;

    // 4. The derived secrets are identical.
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_recipient.to_bytes()
    );

    println!("ECDH-P224 authenticated KEM roundtrip successful!");
    println!("Ciphertext size: {} bytes", ct_bytes.len());

    // --- Example of a failed decapsulation ---

    // Create a different secret key.
    let (_, wrong_secret_key) = EcdhP224::keypair(&mut rng)?;

    // Attempting to decapsulate with the wrong key will fail the tag check.
    let result = EcdhP224::decapsulate(&wrong_secret_key, &ciphertext);
    assert!(result.is_err());

    println!("Decapsulation with the wrong key failed as expected.");

    Ok(())
}
```

## License

This crate is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).