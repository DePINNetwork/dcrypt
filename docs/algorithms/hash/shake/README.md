# SHAKE Fixed-Output Hash Functions

This module provides fixed-output-size implementations of the **SHAKE** (Secure Hash Algorithm and KECCAK) functions as specified in FIPS 202. [1]

While SHAKE is fundamentally an **eXtendable-Output Function (XOF)**, this module provides a conventional hash function interface, making it a convenient drop-in replacement for other hash functions like SHA-256 when a fixed-size digest is desired.

> **Note on Usage:**
> This module provides `Shake128` and `Shake256` as standard fixed-output hash functions. For true **eXtendable-Output Functionality** (i.e., generating an output of arbitrary length), please use the `ShakeXof128` and `ShakeXof256` implementations in the `dcrypt::algorithms::xof::shake` module.

## Overview

The SHAKE functions are based on the Keccak sponge construction, the same foundation as SHA-3. They are named for their security strength rather than their output size. [7] This module provides two main variants:

*   `Shake128`: Offers 128 bits of security against all cryptographic attacks (including collisions) and produces a **fixed 32-byte (256-bit) digest** by default.
*   `Shake256`: Offers 256 bits of security and produces a **fixed 64-byte (512-bit) digest** by default.

The core implementation is designed to be **constant-time** and uses secure memory handling patterns to protect the internal state.

## Domain Separation

Unlike the SHA-3 hash functions which use a `01` domain separator suffix, SHAKE uses a `1111` suffix (`0x1F` in bytes) appended to the input message before padding. This ensures that the output of `Shake128(M)` will not collide with `Sha3-256(M)`, even though they may have the same output length. [2]

## Usage

The SHAKE implementations in this module conform to the standard `HashFunction` trait, allowing for both one-shot and incremental hashing.

### One-Shot Hashing

For simple use cases, the `digest` static method is the most convenient way to compute a hash.

```rust
use dcrypt::algorithms::hash::{Shake128, Shake256, HashFunction};

let data = b"The quick brown fox jumps over the lazy dog";

// Compute a 32-byte (256-bit) digest using SHAKE128
let digest128 = Shake128::digest(data).unwrap();
assert_eq!(digest128.len(), 32);
println!("SHAKE128 Digest (32 bytes): {}", digest128.to_hex());

// Compute a 64-byte (512-bit) digest using SHAKE256
let digest256 = Shake256::digest(data).unwrap();
assert_eq!(digest256.len(), 64);
println!("SHAKE256 Digest (64 bytes): {}", digest256.to_hex());
```

### Incremental (Streaming) Hashing

For large inputs, such as file streams, the incremental API allows you to process data in chunks.

```rust
use dcrypt::algorithms::hash::{Shake256, HashFunction};

let part1 = b"This is part one of a very long message, ";
let part2 = b"and this is the second and final part.";

let mut hasher = Shake256::new();
hasher.update(part1).unwrap();
hasher.update(part2).unwrap();

let digest = hasher.finalize().unwrap();

assert_eq!(digest.len(), 64);
println!("Incremental SHAKE256 Digest: {}", digest.to_hex());
```

### For Extendable-Output (XOF) Functionality

If you require a variable-length output, you must use the `ShakeXof` variants from the `dcrypt::algorithms::xof` module. These provide a `squeeze` method to generate a digest of any desired length.

```rust
use dcrypt::algorithms::xof::{ShakeXof128, ExtendableOutputFunction};

let data = b"Generate a key of arbitrary length";

let mut xof = ShakeXof128::new();
xof.update(data).unwrap();

// Generate a 100-byte output
let mut output = vec![0u8; 100];
xof.squeeze(&mut output).unwrap();

assert_eq!(output.len(), 100);
println!("SHAKE128 XOF Output (100 bytes): {}", hex::encode(&output));
```