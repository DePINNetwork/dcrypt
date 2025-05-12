# Extendable Output Functions (`algorithms/xof`)

This module implements Extendable Output Functions (XOFs). XOFs are cryptographic functions that can produce an output of arbitrary, variable length, unlike traditional hash functions which produce a fixed-size digest. They are typically based on sponge constructions.

XOFs are useful in various cryptographic protocols, including key derivation, mask generation functions (MGFs), and generating pseudorandom data.

## Implemented XOFs

1.  **SHAKE (`shake`)**
    *   **Standard**: FIPS 202
    *   **Description**: Stands for **S**ecure **H**ash **A**lgorithm and **KE**CCAK. SHAKE functions are instances of the Keccak sponge function.
    *   **Variants**:
        *   `ShakeXof128`: Provides 128 bits of security strength. Rate: 1344 bits (168 bytes).
        *   `ShakeXof256`: Provides 256 bits of security strength. Rate: 1088 bits (136 bytes).
    *   **Security Notes**:
        *   Secure when used according to FIPS 202.
        *   The implementation uses `SecureKeccakState` (wrapping `SecretBuffer`) for internal state management to ensure zeroization.
        *   The Keccak-f[1600] permutation is implemented with care for intermediate values using `EphemeralSecret`.
    *   **Core Structs**: `algorithms::xof::shake::ShakeXof128`, `algorithms::xof::shake::ShakeXof256`.
    *   **Distinction**: These are true XOFs, distinct from the fixed-output SHAKE hash functions found in `algorithms::hash::shake`.

2.  **BLAKE3 (`blake3`)**
    *   **Description**: A modern cryptographic hash function that can also operate as an XOF. It is designed for high performance, parallelism, and strong security. Based on a Merkle tree structure over Bao for verified streaming.
    *   **Security Notes**: Offers 256 bits of security. The implementation is adapted from the official reference implementation, focusing on correctness. It supports keyed mode and context string for key derivation.
    *   **Core Struct**: `algorithms::xof::blake3::Blake3Xof`.

## Key Traits

-   **`ExtendableOutputFunction` Trait (`algorithms::xof::ExtendableOutputFunction`)**:
    *   Defines the common interface for XOFs.
    *   Methods:
        *   `new()`: Creates a new XOF instance.
        *   `update(data: &[u8])`: Absorbs input data.
        *   `finalize()`: Finalizes the absorption phase, preparing for squeezing.
        *   `squeeze(output: &mut [u8])`: Fills the output buffer with squeezed bytes.
        *   `squeeze_into_vec(len: usize) -> Vec<u8>`: Squeezes `len` bytes into a new vector.
        *   `reset()`: Resets the XOF to its initial state.
        *   `generate(data: &[u8], len: usize) -> Vec<u8>`: One-shot XOF computation.
    *   Static method: `security_level()`.

-   **`XofAlgorithm` Trait (`algorithms::xof::XofAlgorithm`)**:
    *   Marker trait providing compile-time constants for XOFs: `SECURITY_LEVEL`, `MIN_OUTPUT_SIZE`, `MAX_OUTPUT_SIZE` (optional), `ALGORITHM_ID`.
    *   Includes a `validate_output_length` method.

-   **`KeyedXof` Trait (`algorithms::xof::KeyedXof`)**:
    *   For XOFs that support a keyed mode (e.g., BLAKE3).
    *   Methods: `with_key(key: &[u8])`, `keyed_generate(key: &[u8], data: &[u8], len: usize)`.

-   **`DeriveKeyXof` Trait (`algorithms::xof::DeriveKeyXof`)**:
    *   For XOFs that support a dedicated key derivation mode (e.g., BLAKE3).
    *   Methods: `for_derive_key(context: &[u8])`, `derive_key(context: &[u8], data: &[u8], len: usize)`.

## Usage Example (SHAKE128 XOF)

```rust
use dcrypt_algorithms::xof::shake::ShakeXof128;
use dcrypt_algorithms::xof::ExtendableOutputFunction; // The XOF trait
use dcrypt_algorithms::error::Result;

fn shake128_xof_example() -> Result<()> {
    let input_data = b"Input data for SHAKE128 XOF.";
    let desired_output_length = 64; // Request 64 bytes of output

    // One-shot XOF generation
    let output1 = ShakeXof128::generate(input_data, desired_output_length)?;
    println!("SHAKE128 Output 1 ({} bytes, one-shot): {}", output1.len(), hex::encode(&output1));

    // Incremental XOF usage
    let mut xof_instance = ShakeXof128::new();
    xof_instance.update(b"Input data ")?;
    xof_instance.update(b"for SHAKE128 XOF.")?;
    // finalize() is called implicitly by squeeze if not called manually,
    // or explicitly if you want to separate absorption and squeezing phases.
    xof_instance.finalize()?; // Prepare for squeezing

    let mut output2 = vec![0u8; desired_output_length];
    xof_instance.squeeze(&mut output2)?;
    println!("SHAKE128 Output 2 ({} bytes, incremental): {}", output2.len(), hex::encode(&output2));

    assert_eq!(output1, output2);

    // Squeezing more data from the same instance
    let mut additional_output = [0u8; 32];
    xof_instance.squeeze(&mut additional_output)?; // Continues squeezing
    println!("SHAKE128 Additional Output (32 bytes): {}", hex::encode(&additional_output));
    // Note: output1/output2 will NOT contain additional_output. Squeezing is stateful.

    Ok(())
}

// fn main() {
//     shake128_xof_example().expect("SHAKE128 XOF example failed");
// }
```

## Security Considerations

-   **Security Level**: Choose an XOF variant (e.g., SHAKE128 vs. SHAKE256) that matches the required security level for the application.
-   **Output Length**: While XOFs can produce very long outputs, the effective security strength is determined by the XOF's defined security level (e.g., 128 bits for SHAKE128), not the length of the output. Generating an output longer than twice the security level does not increase resistance against collision attacks beyond the birthday bound of the security level.
-   **Domain Separation**: When using the same XOF for multiple purposes, ensure proper domain separation. For SHAKE, this is typically done by appending different suffix bits (defined in FIPS 202, e.g., `0b1111` for SHAKE itself). BLAKE3 has built-in domain separation via its `flags` and context strings for key derivation.