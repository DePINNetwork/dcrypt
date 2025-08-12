# EdDSA Digital Signature Algorithm (`sign/traditional/ed25519`)

This module provides a production-ready, security-hardened implementation of **Ed25519**, the Edwards-curve Digital Signature Algorithm (EdDSA) variant defined in **RFC 8032**.

The implementation is built from the ground up, including all necessary field, scalar, and point arithmetic for Curve25519. It is designed for correctness, security, and ease of use, conforming to the `dcrypt-api` traits for a consistent cryptographic interface.

-----

### 🛡️ Security Features

Security is the primary design consideration for this module.

  * **Automatic Zeroization**: `Ed25519SecretKey` implements `ZeroizeOnDrop`, ensuring that sensitive key material is automatically cleared from memory when it goes out of scope.
  * **Constant-Time Operations**: Core cryptographic operations are implemented to resist timing-based side-channel attacks.
  * **Type Safety**: The API uses distinct types for public keys, secret keys, and signatures, preventing accidental misuse (e.g., trying to sign with a public key).
  * **Secure API Design**: The API surface is minimal to reduce complexity and the potential for errors. Secret key material is encapsulated and cannot be directly mutated.
  * **Deterministic Signatures**: Following RFC 8032, signature generation is deterministic, which mitigates risks associated with faulty random number generators during the signing process.

-----

### ⚙️ Implementation Details

This module contains a self-contained implementation of all the cryptographic primitives required for Ed25519:

  * **`field.rs`**: Arithmetic for field elements modulo the prime $p = 2^{255} - 19$.
  * **`scalar.rs`**: Arithmetic for scalars modulo the curve order $L$.
  * **`point.rs`**: Edwards curve point addition and scalar multiplication using extended coordinates.
  * **`operations.rs`**: High-level cryptographic functions that combine the primitives.
  * **`ed25519/mod.rs`**: The public-facing implementation of the `Ed25519` signature scheme.

-----

### 🚀 Usage

#### Basic Sign & Verify

All algorithms implement the `dcrypt::api::Signature` trait, providing a consistent and simple API.

```rust
use dcrypt::sign::eddsa::{Ed25519, Ed25519SecretKey, Ed25519PublicKey};
use dcrypt::api::Signature;
use rand::rngs::OsRng;

// 1. Generate a new keypair using a cryptographically secure RNG
let mut rng = OsRng;
let (public_key, secret_key) = Ed25519::keypair(&mut rng).expect("keypair generation failed");

// 2. Sign a message
let message = b"This is a message signed with Ed25519.";
let signature = Ed25519::sign(message, &secret_key).expect("signing failed");

// 3. Verify the signature
let verification_result = Ed25519::verify(message, &signature, &public_key);
assert!(verification_result.is_ok());

println!("Ed25519 signature verified successfully! ✅");

// 4. Verification with a tampered message or wrong key will fail
let tampered_message = b"This is not the original message.";
assert!(Ed25519::verify(tampered_message, &signature, &public_key).is_err());
```

-----

### 🔑 Key Management

#### Storing and Reconstructing Keys

The `Ed25519SecretKey` is derived from a single 32-byte **seed**. For persistence, you only need to securely store this seed. The full secret key, including the public key, can be reconstructed from it at any time.

```rust
use dcrypt::sign::eddsa::{Ed25519, Ed25519SecretKey};
use dcrypt::api::Signature;
use rand::rngs::OsRng;

# fn main() -> dcrypt_api::Result<()> {
// Generate a keypair
let (_public_key, secret_key) = Ed25519::keypair(&mut OsRng)?;

// In a real application, you would securely store this seed.
// IMPORTANT: The `seed` method returns a reference. Clone it for storage.
let seed_to_store: [u8; 32] = *secret_key.seed();

// ... time passes, application restarts ...

// Reconstruct the secret key from the stored seed
let reconstructed_secret = Ed25519SecretKey::from_seed(&seed_to_store)?;

// You can now derive the public key from the reconstructed secret key
let reconstructed_public = reconstructed_secret.public_key()?;

// The reconstructed keys are identical to the original ones and can be used for signing and verification.
let message = b"Verify with a reconstructed key.";
let signature = Ed25519::sign(message, &reconstructed_secret)?;
assert!(Ed25519::verify(message, &signature, &reconstructed_public).is_ok());

println!("Verified signature using a reconstructed key. ✅");
# Ok(())
# }
```

-----

### 📜 Security Guidelines

1.  **Always use a CSPRNG**: Use a strong random number generator like `rand::rngs::OsRng` for key generation.
2.  **Protect Seeds**: The 32-byte seed is the most critical piece of secret material. Encrypt it before storing it to disk and only decrypt it when needed.
3.  **Verify Public Keys**: When receiving a public key, ensure its authenticity through a secure channel or a certificate to prevent man-in-the-middle attacks.
4.  **Clear Sensitive Data**: The `Ed25519SecretKey` handles this automatically. If you handle raw seeds, be sure to zero them from memory after use.