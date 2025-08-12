# Elliptic Curve Cryptography Primitives

This module provides robust, constant-time implementations of various standard elliptic curves. It serves as the foundation for Elliptic Curve Cryptography (ECC) within the `dcrypt` library, enabling operations like key generation, scalar multiplication, and Elliptic Curve Diffie-Hellman (ECDH) key exchange.

The primary focus is on security, particularly resistance to timing-based side-channel attacks. All cryptographic operations involving secret data are designed to execute in constant time.

## Supported Curves

The `ec` module offers a wide range of standard curves to suit different security and performance requirements:

*   **NIST Prime Curves:**
    *   `p192` (sect192r1)
    *   `p224` (sect224r1)
    *   `p256` (sect256r1 or prime256v1)
    *   `p384` (sect384r1)
    *   `p521` (sect521r1)
*   **Koblitz Curve:**
    *   `k256` (secp256k1) - Widely used in cryptocurrencies like Bitcoin and Ethereum.
*   **Binary Curve:**
    *   `b283k` (sect283k1) - A Koblitz curve over a binary field.
*   **Pairing-Friendly Curve:**
    *   `bls12_381` - A modern curve designed for efficient cryptographic pairings, enabling advanced schemes like aggregate signatures.

## Core Features

*   **Constant-Time Implementation**: All scalar multiplications and other operations involving private keys are implemented using constant-time algorithms to mitigate timing side-channel vulnerabilities.
*   **Key Generation**: Securely generate public/private key pairs for any supported curve using `generate_keypair`. This function uses a cryptographically secure random number generator to create a private key (a scalar) and then computes the corresponding public key (a point on the curve).
*   **Scalar Multiplication**: Provides efficient and secure scalar multiplication:
    *   `scalar_mult_base_g`: Fixed-base multiplication with the curve's standard generator point, ideal for public key derivation.
    *   `scalar_mult`: Variable-base multiplication for operations like ECDH.
*   **Point Arithmetic**: Includes fundamental point operations such as addition and doubling, implemented using efficient Jacobian coordinates to minimize costly field inversions.
*   **Point Serialization**: Supports both compressed and uncompressed point serialization formats according to SEC 1 standards, allowing for flexibility between storage size and computational overhead.
*   **Elliptic Curve Diffie-Hellman (ECDH)**: The primitives directly support ECDH key exchange. For each curve, a corresponding Key Derivation Function (KDF) based on HKDF is provided (e.g., `kdf_hkdf_sha256_for_ecdh_kem`) to securely derive a shared symmetric key from the computed point.

## Usage Example: ECDH Key Exchange with P-256

This example demonstrates how two parties, Alice and Bob, can generate an ECDH key pair and compute a shared secret.

```rust
use dcrypt::algorithms::ec::p256::{self, Point, Scalar};
use rand::rngs::OsRng;

fn main() -> Result<(), dcrypt_algorithms::error::Error> {
    // 1. Alice generates her keypair.
    let (alice_private_key, alice_public_key) = p256::generate_keypair(&mut OsRng)?;

    // 2. Bob generates his keypair.
    let (bob_private_key, bob_public_key) = p256::generate_keypair(&mut OsRng)?;

    // 3. Alice computes the shared secret using her private key and Bob's public key.
    let alice_shared_secret_point = p256::scalar_mult(&alice_private_key, &bob_public_key)?;

    // 4. Bob computes the shared secret using his private key and Alice's public key.
    let bob_shared_secret_point = p256::scalar_mult(&bob_private_key, &alice_public_key)?;

    // Both parties arrive at the same point on the curve.
    assert_eq!(alice_shared_secret_point, bob_shared_secret_point);

    // 5. Derive a symmetric key from the shared secret's x-coordinate using a KDF.
    //    Both parties must use the same context string ("info").
    let ikm = alice_shared_secret_point.x_coordinate_bytes();
    let info = Some(b"ecdh-example-context".as_slice());

    let alice_derived_key = p256::kdf_hkdf_sha256_for_ecdh_kem(&ikm, info)?;
    let bob_derived_key = p256::kdf_hkdf_sha256_for_ecdh_kem(&ikm, info)?;

    assert_eq!(alice_derived_key, bob_derived_key);

    println!("ECDH key exchange successful!");
    println!("Derived Symmetric Key: {}", hex::encode(alice_derived_key));

    Ok(())
}
```

## Module Structure

The `ec` module is organized with a dedicated submodule for each curve, such as `p256`, `k256`, etc. Each submodule exports two primary types:

*   **`Point`**: Represents a point on the elliptic curve in affine coordinates. It provides methods for arithmetic, serialization, and validation.
*   **`Scalar`**: Represents an integer in the scalar field of the curve's group order. It is used for private keys and in scalar multiplication operations.

The top-level `ec` module re-exports these types with a clear naming convention (e.g., `P256Point`, `P256Scalar`) for convenient access.

## Benchmarks

Comprehensive benchmarks for all core elliptic curve operations are available in the `benches/` directory. These can be run to measure the performance of field/point arithmetic, key generation, and ECDH on the target machine.