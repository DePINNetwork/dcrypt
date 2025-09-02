# Polynomial Arithmetic Engine

## Overview

The `poly` module provides a generic and high-performance engine for polynomial arithmetic over finite fields, specifically tailored for lattice-based post-quantum cryptography (PQC). It serves as a foundational component for implementing schemes like Dilithium (FIPS 204) and Kyber.

The module is designed with flexibility and security in mind, offering:
*   **Generic Polynomial Representation:** A `Polynomial<M>` struct that is generic over the ring parameters, defined by the `Modulus` and `NttModulus` traits.
*   **High-Performance Arithmetic:** Includes efficient transform methods like the **Number Theoretic Transform (NTT)** and the **Fast Fourier Transform (FFT)** for fast polynomial multiplication (convolution).
*   **Cryptographic Sampling:** Provides standardized methods for sampling polynomial coefficients from uniform and centered binomial distributions (CBD).
*   **Efficient Serialization:** Offers routines for packing and unpacking polynomial coefficients to and from byte arrays.
*   **`no_std` Compatibility:** Fully usable in `no_std` environments with the `alloc` feature.

## Core Concepts

The library is built around a few key abstractions:

*   **`Polynomial<M: Modulus>`**: The central data structure representing a polynomial of degree `N` with coefficients in the ring `Z_Q`. The ring parameters `N` (degree) and `Q` (modulus) are defined by the `M` type parameter.

*   **`Modulus` and `NttModulus` Traits**: These traits define the parameters of the polynomial ring.
    *   `Modulus`: Specifies the coefficient modulus `Q` and the polynomial degree `N`.
    *   `NttModulus`: Extends `Modulus` with parameters required for the Number Theoretic Transform, such as the primitive root of unity (`ZETA`) and precomputed twiddle factors (`ZETAS`).

*   **Parameter Structs**: Concrete implementations of the modulus traits for specific cryptographic schemes.
    *   `DilithiumParams`: Parameters for CRYSTALS-Dilithium as specified in FIPS 204.
    *   `Kyber256Params`: Parameters for CRYSTALS-Kyber.

*   **Samplers**: Traits for generating polynomials with coefficients from specific distributions.
    *   `UniformSampler`: For sampling coefficients uniformly at random.
    *   `CbdSampler`: For sampling from a Centered Binomial Distribution.

## Features

### Polynomial Arithmetic
*   Standard addition, subtraction, and negation of polynomials.
*   Schoolbook multiplication for negacyclic convolution.
*   Fast convolution using transforms like the NTT and FFT.

### Number Theoretic Transform (NTT)
*   **Forward NTT:** Transforms a polynomial from coefficient representation to evaluation representation.
    *   Implements the Decimation-in-Frequency (DIF) Cooley-Tukey algorithm for Dilithium.
    *   Handles conversions to and from the Montgomery domain for Kyber.
*   **Inverse NTT:** Transforms a polynomial back to its coefficient representation.
    *   Implements the Gentleman-Sande (GS) algorithm for Dilithium.
*   **Optimizations:** Uses precomputed twiddle factors for Dilithium and on-the-fly computation for Kyber to ensure high performance.

### Fast Fourier Transform (FFT)
In addition to the NTT, the engine now provides a standard Fast Fourier Transform for polynomial multiplication over rings that may not have NTT-friendly moduli. This is particularly useful for schemes like Falcon.
*   **Forward FFT (`fft`):** Transforms a polynomial from coefficient to evaluation representation.
*   **Inverse FFT (`ifft`):** Transforms a polynomial back to its coefficient form.
*   **Flexibility:** Allows for efficient multiplication in a wider range of cryptographic contexts.

### Cryptographic Sampling
The `DefaultSamplers` struct provides standard implementations for:
*   **Uniform Sampling:** `sample_uniform` uses rejection sampling to generate coefficients uniformly in `Z_Q`.
*   **Centered Binomial Distribution (CBD):** `sample_cbd` generates small coefficients for noise polynomials, crucial for the security of lattice-based schemes.

### Serialization
*   **Coefficient Packing/Unpacking:** The `DefaultCoefficientSerde` provides generic and optimized routines for packing polynomial coefficients into a compact byte representation and unpacking them.
*   **Optimized Routines:** Includes fast, specialized functions like `pack_10bit` and `pack_13bit` for Kyber and Dilithium parameters.

## Usage Examples

### Creating a Polynomial

```rust
use dcrypt::algorithms::poly::polynomial::Polynomial;
use dcrypt::algorithms::poly::params::DilithiumParams;

// Create a new polynomial with all-zero coefficients for the Dilithium ring
let mut poly = Polynomial::<DilithiumParams>::zero();

// Manually set some coefficients
poly.coeffs[0] = 123;
poly.coeffs[1] = 456;

// Create a polynomial from a slice of coefficients
let coeffs: [u32; 256] = { let mut arr = [0; 256]; arr[0] = 1; arr[1] = 2; arr[2] = 3; arr[3] = 4; arr };
let poly_from_slice = Polynomial::<DilithiumParams>::from_coeffs(&coeffs).unwrap();
```

### Polynomial Arithmetic

```rust
use dcrypt::algorithms::poly::polynomial::Polynomial;
use dcrypt::algorithms::poly::params::Kyber256Params;

let a_coeffs: [u32; 256] = { let mut arr = [0; 256]; arr[0] = 10; arr[1] = 20; arr };
let b_coeffs: [u32; 256] = { let mut arr = [0; 256]; arr[0] = 5; arr[1] = 15; arr };
let a = Polynomial::<Kyber256Params>::from_coeffs(&a_coeffs).unwrap();
let b = Polynomial::<Kyber256Params>::from_coeffs(&b_coeffs).unwrap();

// Addition
let sum = &a + &b;
assert_eq!(sum.coeffs[0], 15);
assert_eq!(sum.coeffs[1], 35);

// Subtraction
let diff = &a - &b;
assert_eq!(diff.coeffs[0], 5);
assert_eq!(diff.coeffs[1], 5);
```

### Using the Number Theoretic Transform (NTT) for Fast Multiplication

The NTT is the key to efficient polynomial multiplication in lattice-based cryptography.

```rust
use dcrypt::algorithms::poly::polynomial::{Polynomial, PolynomialNttExt};
use dcrypt::algorithms::poly::params::DilithiumParams;
use dcrypt::algorithms::poly::ntt::{NttOperator, InverseNttOperator};

let p1_coeffs: [u32; 256] = { let mut arr = [0; 256]; arr[0] = 1; arr[1] = 2; arr[2] = 3; arr };
let p2_coeffs: [u32; 256] = { let mut arr = [0; 256]; arr[0] = 4; arr[1] = 5; arr };
let mut p1 = Polynomial::<DilithiumParams>::from_coeffs(&p1_coeffs).unwrap();
let mut p2 = Polynomial::<DilithiumParams>::from_coeffs(&p2_coeffs).unwrap();

// Transform polynomials to the NTT domain
p1.ntt_inplace().unwrap();
p2.ntt_inplace().unwrap();

// Perform fast pointwise multiplication in the NTT domain
let mut product_ntt = p1.ntt_mul(&p2);

// Transform the result back to the coefficient domain
product_ntt.from_ntt_inplace().unwrap();

// The result is the negacyclic convolution of the original polynomials
let expected = Polynomial::<DilithiumParams>::from_coeffs(&p1_coeffs).unwrap().schoolbook_mul(
    &Polynomial::<DilithiumParams>::from_coeffs(&p2_coeffs).unwrap()
);
assert_eq!(product_ntt, expected);
```

### Using the Fast Fourier Transform (FFT) for Multiplication

The FFT provides another method for fast convolution, especially useful when ring parameters are not NTT-friendly.

```rust
use dcrypt::algorithms::poly::prelude::{fft, ifft};
use dcrypt::algorithms::poly::polynomial::Polynomial;
use dcrypt::algorithms::poly::params::DilithiumParams;

// Note: This example uses DilithiumParams for API consistency, though FFT
// is typically used for schemes without NTT-friendly moduli.
let p1_coeffs: [u32; 256] = { let mut arr = [0; 256]; arr[0] = 1; arr[1] = 2; arr[2] = 3; arr };
let p2_coeffs: [u32; 256] = { let mut arr = [0; 256]; arr[0] = 4; arr[1] = 5; arr };
let p1 = Polynomial::<DilithiumParams>::from_coeffs(&p1_coeffs).unwrap();
let p2 = Polynomial::<DilithiumParams>::from_coeffs(&p2_coeffs).unwrap();


// 1. Transform polynomials to the evaluation domain using FFT
// (The FFT implementation would typically convert coefficients to a floating-point type)
// let mut p1_eval = ...;
// fft(&mut p1_eval);
// let mut p2_eval = ...;
// fft(&mut p2_eval);

// 2. Perform pointwise multiplication in the evaluation domain
// product_eval = p1_eval.pointwise_mul(&p2_eval);

// 3. Transform back to the coefficient domain
// ifft(&mut product_eval);

// After rounding and modular reduction, the result would match schoolbook multiplication.
// let expected = p1.schoolbook_mul(&p2);
// assert_eq!(product_eval_rounded, expected);
```

### Sampling Polynomials

Cryptographic sampling is essential for key generation and encryption in lattice schemes.

```rust
use dcrypt::algorithms::poly::sampling::{DefaultSamplers, UniformSampler, CbdSampler};
use dcrypt::algorithms::poly::params::DilithiumParams;
use rand::rngs::OsRng;

// Sample a polynomial with coefficients uniformly at random from Z_Q
let a = DefaultSamplers::sample_uniform::<DilithiumParams>(&mut OsRng).unwrap();

// Sample a small noise polynomial using the Centered Binomial Distribution (eta=2)
let s1 = DefaultSamplers::sample_cbd::<DilithiumParams>(&mut OsRng, 2).unwrap();
```

### Packing and Unpacking Coefficients

Efficiently serialize polynomials for storage or transmission.

```rust
use dcrypt::algorithms::poly::polynomial::Polynomial;
use dcrypt::algorithms::poly::params::Kyber256Params;
use dcrypt::algorithms::poly::serialize::{DefaultCoefficientSerde, CoefficientPacker, CoefficientUnpacker};

let coeffs: [u32; 256] = { let mut arr = [0; 256]; arr[0] = 1023; arr[1] = 511; arr[2] = 1; arr };
let poly = Polynomial::<Kyber256Params>::from_coeffs(&coeffs).unwrap();

// Pack the 10-bit coefficients into a byte array
let packed_bytes = DefaultCoefficientSerde::pack_10bit::<Kyber256Params>(&poly).unwrap();
assert_eq!(packed_bytes.len(), 320); // 256 * 10 / 8

// Unpack the bytes back into a polynomial
let unpacked_poly = DefaultCoefficientSerde::unpack_10bit::<Kyber256Params>(&packed_bytes).unwrap();
assert_eq!(poly, unpacked_poly);
```