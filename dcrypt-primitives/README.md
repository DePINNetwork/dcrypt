# DCRYPT-Primitives

Cryptographic primitives for the DCRYPT library with full support for `no_std` environments.

## Features

DCRYPT-Primitives can be tailored for your specific requirements through feature flags:

- **std** (default): Enables standard library support
- **alloc**: Enables heap allocations without full std
- **hash**: Enables hash function implementations
- **xof**: Enables extendable output functions (requires alloc)
- **aead**: Enables authenticated encryption (requires alloc)
- **block**: Enables block cipher implementations
- **kdf**: Enables key derivation functions (requires alloc)
- **mac**: Enables message authentication codes
- **stream**: Enables stream cipher implementations
- **simd**: Enables SIMD optimizations
- **wasm**: Enables WebAssembly optimizations

## Usage Examples

### Standard Environment

```rust
use dcrypt_primitives::hash::{HashFunction, Sha256};
use dcrypt_primitives::aead::Gcm;
use dcrypt_primitives::block::aes::Aes128;

fn main() {
    // Generate a hash
    let hash = Sha256::digest(b"Hello, DCRYPT!").unwrap();
    println!("SHA-256: {}", hex::encode(&hash));
    
    // Use AEAD mode
    let key = [0x42; 16];
    let nonce = [0x24; 12];
    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    
    let ciphertext = gcm.encrypt(b"Secret message", None).unwrap();
    println!("Encrypted: {}", hex::encode(&ciphertext));
}
```

### No-std Environment with Alloc

```rust
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use dcrypt_primitives::hash::{HashFunction, Sha256};
use dcrypt_primitives::block::aes::Aes128;
use dcrypt_primitives::aead::Gcm;

fn example() {
    // Hash with SHA-256
    let hash = Sha256::digest(b"Hello, no_std!").unwrap();
    
    // Use AEAD mode
    let key = [0x42; 16];
    let nonce = [0x24; 12];
    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    
    let ciphertext = gcm.encrypt(b"Secret message", None).unwrap();
}
```

## Build Commands

```bash
# With default features (includes std)
cargo build

# Without std but with alloc
cargo build --no-default-features --features alloc

# With specific module features
cargo build --no-default-features --features "alloc,hash,block"
```

## Feature Combinations Guide

| Use Case | Recommended Features |
|----------|---------------------|
| Complete functionality | `default` (enables everything) |
| No-std with allocator | `alloc`, `hash`, `block`, `mac` |
| Minimal encryption only | `block` |
| AEAD with GCM | `alloc`, `aead`, `block` |
| Password hashing | `alloc`, `kdf` |

## License

Apache License, Version 2.0