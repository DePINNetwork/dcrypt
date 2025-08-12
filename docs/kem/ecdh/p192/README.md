# ECDH-KEM with NIST P-192 (`secp192r1`)

This module provides a Key Encapsulation Mechanism (KEM) based on the Elliptic Curve Diffie-Hellman (ECDH) protocol over the NIST P-192 curve (also known as `secp192r1`).

It offers a concrete implementation of the `dcrypt::api::Kem` trait, ensuring a consistent and secure interface.

## Security Warning

The NIST P-192 curve provides approximately **80 bits of security**. This is **below the modern standard of 128 bits** and is generally considered **insecure for new applications**. It is included primarily for legacy protocol support or specific interoperability requirements.

**For new development, it is strongly recommended to use a more secure curve like `EcdhP256` (128-bit security) or higher.**

## Features

-   **Type-Safe API:** Leverages specific types (`EcdhP192PublicKey`, `EcdhP192SecretKey`) to prevent the misuse or accidental mixing of keys from different curves at compile time.
-   **Secure Key Derivation:** Implements a robust KDF based on **HKDF-SHA256**. The KDF input binds the ephemeral and static public keys to the derived shared secret, conforming to modern best practices.
-   **Automatic Zeroization:** Both the `EcdhP192SecretKey` and `EcdhP192SharedSecret` types implement `ZeroizeOnDrop`, ensuring sensitive data is automatically cleared from memory when it is no longer in use.
-   **Point Validation:** All public keys and ciphertexts are validated to ensure they represent valid points on the P-192 curve and are not the identity point, mitigating invalid curve attacks.
-   **Bandwidth Efficiency:** Uses compressed point format for all public keys and ciphertexts, minimizing data transmission size.

## API and Data Structures

The following types are central to this module's functionality:

| Type | Represents | Size |
| :--- | :--- | :--- |
| `EcdhP192PublicKey` | A public key (compressed point) | **25 bytes** |
| `EcdhP192SecretKey` | A secret key (scalar) | **24 bytes** |
| `EcdhP192Ciphertext` | An encapsulated key (ephemeral public key) | **25 bytes** |
| `EcdhP192SharedSecret`| A derived shared secret (KDF output) | **32 bytes** |

## Usage Example

The interface is consistent with all other KEMs in the `dcrypt` library.

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::p192::{
    EcdhP192, EcdhP192PublicKey, EcdhP192SecretKey, EcdhP192Ciphertext
};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Recipient generates a key pair.
    let (public_key, secret_key) = EcdhP192::keypair(&mut rng)?;
    println!("Generated P-192 key pair.");

    // The public key can be serialized for distribution.
    let pk_bytes = public_key.to_bytes();
    assert_eq!(pk_bytes.len(), 25);

    // 2. Sender receives the public key bytes, restores the key,
    //    and encapsulates a shared secret.
    let restored_pk = EcdhP192PublicKey::from_bytes(&pk_bytes)?;
    let (ciphertext, shared_secret_sender) = EcdhP192::encapsulate(&mut rng, &restored_pk)?;
    println!("Encapsulated a shared secret.");

    // The ciphertext is sent to the recipient.
    let ct_bytes = ciphertext.to_bytes();
    assert_eq!(ct_bytes.len(), 25);

    // 3. Recipient receives the ciphertext, restores it, and uses their
    //    secret key to decapsulate and derive the same shared secret.
    let restored_ct = EcdhP192Ciphertext::from_bytes(&ct_bytes)?;
    let shared_secret_recipient = EcdhP192::decapsulate(&secret_key, &restored_ct)?;
    println!("Decapsulated to recover the shared secret.");

    // 4. Both parties now have the identical secret.
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_recipient.to_bytes()
    );
    assert_eq!(shared_secret_sender.to_bytes().len(), 32);

    println!("\nSuccess! Shared secrets match.");
    println!("-> Public Key Size:      {} bytes", pk_bytes.len());
    println!("-> Secret Key Size:      {} bytes", secret_key.to_bytes().len());
    println!("-> Ciphertext Size:      {} bytes", ct_bytes.len());
    println!("-> Derived Secret Size:  {} bytes", shared_secret_sender.to_bytes().len());

    Ok(())
}
```

## Performance Benchmarks

This module includes a dedicated benchmark suite to measure its performance characteristics. You can run it using the following command:

```bash
cargo bench --bench ecdh_p192
```

The results, which include measurements for key generation, encapsulation, and decapsulation, will be generated in the `target/criterion/` directory.

## License

This crate is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).