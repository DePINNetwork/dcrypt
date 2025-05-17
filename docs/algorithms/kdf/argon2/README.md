# Argon2 Key Derivation Function (`algorithms/kdf/argon2`)

## Overview

Argon2 is a modern, memory-hard password hashing and key derivation function designed to be resistant against various attacks including GPU cracking attacks, time-memory trade-offs, and side-channel attacks. It was the winner of the 2015 Password Hashing Competition (PHC).

This implementation follows RFC 9106 specifications with proper error handling, configurability, and robust security properties.

## Variants

The implementation supports all three official Argon2 variants:

- **Argon2d** (`Algorithm::Argon2d`): Maximizes resistance to GPU cracking attacks through data-dependent memory access. This offers the highest resistance against GPU attacks but may be vulnerable to side-channel attacks.

- **Argon2i** (`Algorithm::Argon2i`): Uses data-independent memory access to protect against side-channel attacks. This provides better protection against side-channel attacks but less resistance against GPU attacks.

- **Argon2id** (`Algorithm::Argon2id`): A hybrid approach that combines features of both Argon2d and Argon2i. It uses Argon2i for the first half of the first pass and Argon2d for the rest. This is generally recommended for password hashing as it provides a good balance of security properties.

## Parameters

Argon2 is highly configurable through the `Params<S>` struct:

```rust
pub struct Params<const S: usize> where Salt<S>: Argon2Compatible {
    pub argon_type: Algorithm,       // Argon2 variant (d, i, or id)
    pub version: u32,                // Argon2 version (0x13 for v1.3)
    pub memory_cost: u32,            // Memory usage in KiB
    pub time_cost: u32,              // Number of iterations
    pub parallelism: u32,            // Degree of parallelism (lanes)
    pub output_len: usize,           // Length of output hash in bytes
    pub salt: Salt<S>,               // Salt value
    pub ad: Option<Zeroizing<Vec<u8>>>,     // Optional associated data
    pub secret: Option<Zeroizing<Vec<u8>>>, // Optional secret key
}
```

### Parameter Recommendations

- **Memory Cost**: Set as high as your system can tolerate. Higher values increase resistance to GPU attacks.
- **Time Cost**: Number of iterations through the memory matrix. Higher values increase computational cost.
- **Parallelism**: Should be set according to available CPU cores for optimal performance.
- **Salt**: Must be at least 8 bytes (16 bytes recommended) and should be unique for each hashed password.
- **Associated Data**: Optional context information that will be included in the hash calculation.
- **Secret**: Optional key that can be used to further protect against rainbow table attacks.

## Usage

### Basic Usage

```rust
use dcrypt_algorithms::kdf::argon2::{Argon2, Algorithm, Params};
use dcrypt_algorithms::types::Salt;
use common::security::SecretVec;

// Create a salt
const SALT_SIZE: usize = 16;
let salt_bytes = [0x02; SALT_SIZE];
let salt = Salt::<SALT_SIZE>::new(salt_bytes);

// Configure Argon2 parameters
let params = Params {
    argon_type: Algorithm::Argon2id,  // Recommended variant
    version: 0x13,                    // v1.3
    memory_cost: 65536,               // 64 MB
    time_cost: 2,                     // 2 iterations
    parallelism: 4,                   // 4 threads
    output_len: 32,                   // 32-byte output
    salt,
    ad: None,                         // No associated data
    secret: None,                     // No secret
};

// Create Argon2 instance
let argon2 = Argon2::<SALT_SIZE>::new_with_params(params);

// Hash a password
let password = SecretVec::from_slice(b"my_secure_password");
let hash = argon2.hash_password(password.as_ref()).expect("Hashing failed");
```

### Password Hashing and Verification

```rust
use dcrypt_algorithms::kdf::argon2::{Argon2, Algorithm, Params};
use dcrypt_algorithms::kdf::PasswordHashFunction;
use dcrypt_algorithms::types::{Salt, SecretBytes};

// Password to hash
let password = SecretBytes::<32>::new(*b"my_secure_password\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

// Configure parameters for password hashing
const SALT_SIZE: usize = 16;
let salt = Argon2::<SALT_SIZE>::generate_salt(&mut rand::rngs::OsRng);

let params = Params {
    argon_type: Algorithm::Argon2id,
    version: 0x13,
    memory_cost: 65536,
    time_cost: 2,
    parallelism: 4,
    output_len: 32,
    salt,
    ad: None,
    secret: None,
};

// Create Argon2 instance
let argon2 = Argon2::<SALT_SIZE>::new_with_params(params);

// Hash password and create PHC-format hash
let password_hash = argon2.hash_password(&password).expect("Hashing failed");

// Verify password against stored hash
let is_valid = argon2.verify(&password, &password_hash).expect("Verification failed");
assert!(is_valid);
```

### Key Derivation

```rust
use dcrypt_algorithms::kdf::argon2::{Argon2, Algorithm, Params};
use dcrypt_algorithms::kdf::{KeyDerivationFunction, KdfOperation};
use dcrypt_algorithms::types::Salt;

const SALT_SIZE: usize = 16;
let salt = Salt::<SALT_SIZE>::random(&mut rand::rngs::OsRng).expect("Salt generation failed");

let params = Params {
    argon_type: Algorithm::Argon2id,
    version: 0x13,
    memory_cost: 32768,
    time_cost: 3,
    parallelism: 2,
    output_len: 32,
    salt,
    ad: None,
    secret: None,
};

let argon2 = Argon2::<SALT_SIZE>::new_with_params(params);

// Input key material
let ikm = b"my input key material";

// Derive key using the direct method
let derived_key = argon2.derive_key(
    ikm,
    None,            // Use salt from params
    None,            // No additional info
    0                // Use default output length
).expect("Key derivation failed");

// Or use the builder pattern
let derived_key_via_builder = argon2.builder()
    .with_ikm(ikm)
    .with_output_length(64)  // Override output length
    .derive()
    .expect("Key derivation failed");
```

## Implementation Details

This implementation is fully compliant with RFC 9106 and includes:

- Complete support for all Argon2 variants (d, i, id)
- Support for the PHC string format for password hashing
- Proper validation of all parameters
- Secure management of sensitive data using `Zeroizing`
- Protection against timing attacks using constant-time comparisons
- Comprehensive test coverage including all RFC 9106 test vectors

### Core Algorithm Components

The implementation includes the following key components:

1. **H₀** Pre-hash function: Uses BLAKE2b with specific parameters to hash the initial inputs
2. **H′** Variable-length hash function: Extending BLAKE2b for various output lengths
3. **G** Mixing function: Implements the Argon2 G mixing function with BLAMKA rounds
4. Data-dependent and data-independent addressing modes
5. Memory matrix manipulation with proper synchronization points
6. Password verification with constant-time comparisons

### Security Considerations

- Always use a unique, cryptographically random salt for each password hash
- Set memory cost as high as possible for your environment (minimum 32 MB recommended)
- Use a time cost of at least 2 iterations
- For sensitive applications, consider using a secret key
- For highest resistance to both GPU and side-channel attacks, use Argon2id variant
- Verify compatibility with RFC 9106 test vectors (included in test suite)

## Traits and Interfaces

The Argon2 implementation implements the following traits:

- `KeyDerivationFunction`: For general key derivation purposes
- `PasswordHashFunction`: Specifically for password hashing and verification
- `ParamProvider`: For configuration parameter management
- `KdfOperation`: For builder pattern operations

## References

- [RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications](https://datatracker.ietf.org/doc/html/rfc9106)
- [Password Hashing Competition (PHC)](https://www.password-hashing.net/)