# DCRYPT - Pure Rust Cryptographic Library

DCRYPT is a pure Rust cryptographic library that provides both traditional and post-quantum cryptographic algorithms. The library is designed with a strong focus on security, modularity, performance, and usability, while eliminating foreign function interfaces (FFI) to ensure memory safety and cross-platform compatibility.

## Key Features

- **Pure Rust Implementation**: All cryptographic algorithms implemented entirely in Rust without FFI
- **Comprehensive Algorithm Support**: Both traditional and post-quantum cryptographic algorithms
- **Modular Architecture**: Organized as a workspace with multiple crates
- **Strong Type Safety**: Leverages Rust's type system to prevent misuse
- **Memory Protection**: Uses zeroizing for sensitive data
- **Hybrid Cryptography Support**: Ready-to-use combinations of traditional and post-quantum algorithms
- **Cross-Platform Support**: Works across various platforms with both `std` and `no_std` environments

## Getting Started

Add DCRYPT to your `Cargo.toml`:

```toml
[dependencies]
dcrypt = "0.1.0"
```

## Examples

See the `examples/` directory for usage examples.

## Documentation

For detailed documentation, run:

```bash
cargo doc --open
```

## License

Licensed under either of:

- MIT license
- Apache License, Version 2.0

at your option.


# SHAKE Implementation Notes

This codebase contains two different SHAKE implementations:

1. **Fixed-Output Hash Functions** (`src/hash/shake.rs`)
   - `Shake128`: Fixed output size of 32 bytes (256 bits)
   - `Shake256`: Fixed output size of 64 bytes (512 bits)
   - Uses the `HashFunction` trait
   - Good for applications where a fixed-size hash is needed

2. **Extendable Output Functions (XOFs)** (`src/xof/shake/mod.rs`)
   - `ShakeXof128`: Variable output size with 128-bit security strength
   - `ShakeXof256`: Variable output size with 256-bit security strength
   - Uses the `ExtendableOutputFunction` trait
   - Good for applications where variable-length outputs are needed

## Test Vector Organization

The test suite is split to accommodate both implementations:

- Fixed-output tests in `src/hash/shake.rs`: These only test with the fixed output size (32/64 bytes)
- Variable-output tests in `src/xof/shake/tests.rs`: These test with various output sizes

## NIST Test Vectors

The NIST test vectors are organized as follows:
- `SHAKE128ShortMsg.rsp`, `SHAKE256ShortMsg.rsp`: Short message tests
- `SHAKE128LongMsg.rsp`, `SHAKE256LongMsg.rsp`: Long message tests
- `SHAKE128VariableOut.rsp`, `SHAKE256VariableOut.rsp`: Variable output tests

## Implementation Details

Both implementations follow FIPS 202 with:
- Domain separation value of 0x1F for SHAKE
- Final padding with 0x80
- Proper keccak-f[1600] permutation


## Post-Quantum Algorithms: Support for NIST PQC candidates (Kyber, Dilithium, NTRU)