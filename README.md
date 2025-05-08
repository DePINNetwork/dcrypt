# DCRYPT - Pure Rust Cryptographic Library

DCRYPT is a pure Rust cryptographic library implementing both traditional and post-quantum cryptographic algorithms. Built with security, modularity, and usability as core principles, it eliminates foreign function interfaces (FFI) to ensure memory safety and cross-platform compatibility.

## Key Features

- **Pure Rust Implementation**: All algorithms implemented entirely in Rust without FFI
- **Comprehensive Algorithm Support**: Both traditional and post-quantum cryptography
- **Modular Architecture**: Organized as a workspace with specialized crates
- **Strong Type Safety**: Leverages Rust's type system to prevent misuse
- **Memory Protection**: Automatic zeroizing for sensitive data
- **Hybrid Cryptography**: Ready-to-use combinations of traditional and post-quantum algorithms
- **Cross-Platform**: Works in both `std` and `no_std` environments

## Quick Start

Add DCRYPT to your `Cargo.toml`:

```toml
[dependencies]
dcrypt = "0.1.0"
```

Basic Kyber key encapsulation example:

```rust
use dcrypt::prelude::*;

// Generate a keypair
let (public_key, secret_key) = Kyber768::keypair(&mut rand::thread_rng())?;

// Encapsulate a shared secret
let (ciphertext, shared_secret_sender) = 
    Kyber768::encapsulate(&mut rand::thread_rng(), &public_key)?;

// Decapsulate the shared secret
let shared_secret_receiver = Kyber768::decapsulate(&secret_key, &ciphertext)?;

// The shared secrets will be identical
assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref());
```

## Library Structure

DCRYPT is organized into several specialized crates:

### dcrypt-core

The foundation providing:
- Common traits (`Kem`, `Signature`, `SymmetricCipher`, `Serialize`)
- Comprehensive error handling
- Constant-time operations to prevent timing attacks
- Secure memory handling with `ZeroGuard`
- Mathematical primitives for cryptographic operations
- Base types with zeroizing capabilities (`Key`, `PublicKey`, `Ciphertext`)

### dcrypt-constants

A centralized repository of cryptographic parameters:
- Constants for traditional algorithms (RSA, DSA, ECDH, etc.)
- Parameters for post-quantum algorithms (Kyber, Dilithium, NTRU, etc.)
- Hash function and symmetric encryption constants
- Support for different security levels (e.g., Kyber-512/768/1024)

### dcrypt-primitives

Foundational cryptographic algorithms:
- **Hash Functions**: SHA-2 and SHA-3 families
- **Extendable Output Functions**: SHAKE-128/256 and BLAKE3
- **Block Ciphers**: AES with CBC, CTR, and GCM modes
- **Stream Ciphers**: ChaCha20
- **MACs**: Poly1305
- **Authenticated Encryption**: ChaCha20Poly1305, XChaCha20Poly1305

All implementations feature extensive test coverage using official NIST and RFC test vectors, memory protection with zeroizing, and constant-time operations where security requires it.

### dcrypt-symmetric

High-level symmetric encryption:
- **AEAD Ciphers**: AES-GCM and ChaCha20Poly1305
- **Key Management**: Generation, storage, and password-based derivation
- **Structured Formats**: Ciphertext packages with serialization support
- **Streaming APIs**: Memory-efficient encryption for large files

### dcrypt (main interface)

The primary crate that:
- Re-exports all cryptographic algorithms
- Provides high-level, easy-to-use APIs
- Organizes algorithms into clear modules
- Includes a prelude for commonly used items

## Algorithm Support

### Key Encapsulation Mechanisms (KEM)
- **Traditional**: RSA (2048/4096), DH, ECDH (P-256/P-384)
- **Post-Quantum**: Kyber (512/768/1024), NTRU, Saber, McEliece
- **Hybrid**: RSA+Kyber, ECDH+Kyber, ECDH+NTRU

### Digital Signatures
- **Traditional**: Ed25519, ECDSA, RSA (PSS/PKCS1), DSA
- **Post-Quantum**: Dilithium, Falcon, SPHINCS+, Rainbow
- **Hybrid**: ECDSA+Dilithium, RSA+Falcon

## More Examples

### Symmetric Encryption with AES-GCM

```rust
use dcrypt::prelude::*;
use dcrypt_symmetric::aes::{Aes256Key, Aes256Gcm, GcmNonce};
use dcrypt_symmetric::cipher::{SymmetricCipher, Aead};

// Generate a random key
let key = Aes256Key::generate();
let cipher = Aes256Gcm::new(&key);

// Encrypt data with authentication
let plaintext = b"Confidential message";
let nonce = Aes256Gcm::generate_nonce();
let ciphertext = cipher.encrypt(&nonce, plaintext, None)?;

// Decrypt data
let decrypted = cipher.decrypt(&nonce, &ciphertext, None)?;
assert_eq!(decrypted, plaintext);
```

### Digital Signature Example

```rust
use dcrypt::prelude::*;
use dcrypt::signature::ed25519::{Ed25519, Ed25519PublicKey, Ed25519SecretKey};

// Generate a keypair
let (public_key, secret_key) = Ed25519::keypair(&mut rand::thread_rng())?;

// Sign a message
let message = b"This message needs to be authenticated";
let signature = Ed25519::sign(message, &secret_key)?;

// Verify the signature
let verification = Ed25519::verify(message, &signature, &public_key);
assert!(verification.is_ok());
```

See the `examples/` directory for more usage examples including Dilithium, DSA, ECDSA, Kyber, NTRU, McEliece, and RSA operations.

## Security Features

- **Constant-Time Operations**: Critical comparisons use constant-time implementations
- **Secure Memory Handling**: Automatic zeroing of sensitive data using `Zeroize`
- **Type Safety**: Strong typing to prevent misuse of cryptographic primitives
- **Error Handling**: Clear feedback without leaking sensitive information
- **Minimal Unsafe Code**: Reduces potential vulnerabilities

## Feature Flags

- **std** (default): Standard library support
- **no_std**: For embedded environments
- **wasm**: WebAssembly optimizations
- **simd**: SIMD acceleration where available
- **serde**: Serialization/deserialization support

## License

Apache License, Version 2.0

## Contributing

Contributions are welcome! Please ensure:
- Code follows Rust style guidelines
- All tests pass
- New features are properly documented
- Security considerations are addressed

Thank you for considering contributing to DCRYPT!