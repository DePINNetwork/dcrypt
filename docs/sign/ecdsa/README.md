# ECDSA Signature Implementations (`sign::traditional::ecdsa`)

This module provides secure and compliant implementations of the **Elliptic Curve Digital Signature Algorithm (ECDSA)** as specified in **FIPS 186-4**. It supports the standard NIST prime curves and is designed for robust, general-purpose use.

All schemes implement the `dcrypt_api::Signature` trait for a consistent and safe developer experience.

-----

## NIST Curves Supported  elliptic-curves

The module provides implementations for the following NIST-recommended curves, each paired with its standard hash function as per FIPS 186-5 recommendations.

| Struct Name | NIST Curve | Scalar Size | Hash Function | Status |
| :--- | :--- | :--- | :--- | :--- |
| **`EcdsaP192`** | `secp192r1` | 24 bytes | `SHA-256` | ✅ Implemented |
| **`EcdsaP224`** | `secp224r1` | 28 bytes | `SHA-224` | ✅ Implemented |
| **`EcdsaP256`** | `secp256r1` | 32 bytes | `SHA-256` | ✅ Implemented |
| **`EcdsaP384`** | `secp384r1` | 48 bytes | `SHA-384` | ✅ Implemented |
| **`EcdsaP521`** | `secp521r1` | 66 bytes | `SHA-512` | ✅ Implemented |

-----

## ✨ Features

  * **Standards Compliant**: Follows the specifications in **FIPS 186-4** for signature generation and verification.
  * **Secure Nonce Generation**: Implements deterministic nonce (`k`) generation based on **RFC 6979**, hedged with additional entropy from a CSPRNG. This approach prevents catastrophic key failure due to nonce reuse or a weak RNG, as recommended by **FIPS 186-5**.
  * **Side-Channel Resistance**: Final verification comparisons are performed using constant-time functions to mitigate timing attacks.
  * **Secure Key Handling**: Secret key types implement `Zeroize` on `Drop`, ensuring that sensitive key material is automatically cleared from memory when it goes out of scope.
  * **Type Safety**: Each curve (`P-256`, `P-384`, etc.) has distinct public key, secret key, and signature types. This prevents accidental misuse, such as trying to verify a `P-256` signature with a `P-384` key.

-----

## 🚀 Usage Example (P-256)

The API is consistent across all supported curves. Here is an example using `EcdsaP256`.

```rust
use dcrypt::sign::ecdsa::EcdsaP256;
use dcrypt::api::Signature;
use rand::rngs::OsRng;

fn main() -> dcrypt::api::Result<()> {
    // 1. Generate a new keypair using a cryptographically secure RNG.
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP256::keypair(&mut rng)?;

    // 2. Define the message to be signed.
    let message = b"This message will be signed with ECDSA P-256.";

    // 3. Sign the message using the secret key.
    // The signature nonce 'k' is generated deterministically (RFC 6979)
    // with additional entropy for enhanced security.
    let signature = EcdsaP256::sign(message, &secret_key)?;
    println!("Signature generated successfully.");

    // 4. Verify the signature using the public key.
    let verification_result = EcdsaP256::verify(message, &signature, &public_key);
    assert!(verification_result.is_ok());
    println!("Signature is valid! ✅");

    // 5. Demonstrate that verification fails with a different message.
    let tampered_message = b"This is not the original message.";
    assert!(EcdsaP256::verify(tampered_message, &signature, &public_key).is_err());
    println!("Verification correctly failed for tampered message. ❌");

    Ok(())
}
```

-----

## Signature Format

Signatures are encoded using the standard **ASN.1 DER (Distinguished Encoding Rules)** format, as is common for ECDSA. The structure is a `SEQUENCE` containing two `INTEGER` values, `r` and `s`.

```
SEQUENCE {
  r INTEGER,
  s INTEGER
}
```

The `common.rs` file in this module contains the logic for serializing and deserializing this structure.

-----

## 🛡️ Security Considerations

  * **Secret Key Management**: The `EcdsaP<NNN>SecretKey` types are designed to be secure, but the underlying key material (the raw bytes) must still be stored and handled with extreme care. Always use encrypted storage for secret keys at rest.
  * **Public Key Authenticity**: When verifying a signature, you must have confidence that the public key belongs to the claimed entity. Use a secure method (like a PKI or a trusted channel) to obtain public keys.
  * **Algorithm Choice**: While all implemented curves are secure, **`EcdsaP256`** is the most common choice and provides a 128-bit security level, which is sufficient for most modern applications.