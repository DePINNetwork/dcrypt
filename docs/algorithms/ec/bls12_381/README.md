# BLS12-381 Pairing-Friendly Curve

## Overview

This module provides a pure-Rust implementation of the BLS12-381 pairing-friendly elliptic curve. It is designed to support advanced cryptographic schemes that rely on bilinear pairings, such as aggregate signatures, threshold signatures, and certain zero-knowledge proof systems.

> **Warning:** This is a low-level cryptographic implementation and has not been independently audited. Use at your own risk.

## Core Concepts

The BLS12-381 curve construction involves three distinct cryptographic groups:

*   **Group G₁**: A group of elliptic curve points defined over the base field Fₚ. In this implementation, these are represented by the `G1Affine` and `G1Projective` types.
*   **Group G₂**: A group of elliptic curve points defined over a quadratic extension field Fₚ². These are represented by the `G2Affine` and `G2Projective` types.
*   **Target Group Gₜ**: A multiplicative group over a twelfth-degree extension field Fₚ¹². The pairing function maps pairs of points from G₁ and G₂ into this group. It is represented by the `Gt` type.

The central feature of this curve is the **bilinear pairing**, which is a special map `e: G₁ × G₂ → Gₜ` with the following property:

`e(aP, bQ) = e(P, Q)^(ab)`

where `P` is a point in G₁, `Q` is a point in G₂, and `a` and `b` are scalars. This property allows for novel cryptographic constructions that are not possible with traditional elliptic curves.

## Features

*   **Pairing Implementation**: An efficient implementation of the optimal Ate pairing, including the Miller loop (`multi_miller_loop`) and the final exponentiation.
*   **Group Arithmetic**: Complete implementations for group operations in G₁, G₂, and Gₜ, including point addition, doubling, and negation.
*   **Coordinate Systems**: Both Affine and Jacobian Projective coordinates are used for points in G₁ and G₂, with projective coordinates being used internally for efficient, inversion-free arithmetic.
*   **Scalar Field Arithmetic**: A full implementation of the scalar field Fₙ, including arithmetic operations and modular inversion.
*   **Finite Field Tower**: The underlying tower of finite fields (Fₚ, Fₚ², Fₚ⁶, Fₚ¹²) required for the pairing is implemented in the `field` submodule.
*   **Serialization**: Support for both compressed and uncompressed point serialization for points in G₁ and G₂.
*   **Security Hardening**: Includes constant-time scalar multiplication, subgroup checks (`is_torsion_free`), and cofactor clearing to protect against a range of cryptographic attacks.

## Usage Example: Verifying the Bilinearity Property

The following example demonstrates the core bilinear property of the pairing function.

```rust
use dcrypt::algorithms::ec::bls12_381::{
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};

fn main() {
    // 1. Get the standard generator points for G1 and G2.
    let p_g1 = G1Affine::generator();
    let q_g2 = G2Affine::generator();

    // 2. Create two random scalars (representing private keys).
    let a = Scalar::from(12345u64);
    let b = Scalar::from(67890u64);

    // 3. Compute the corresponding points (representing public keys).
    //    aP = [a]P and bQ = [b]Q
    let ap = G1Affine::from(G1Projective::from(p_g1) * a);
    let bq = G2Affine::from(G2Projective::from(q_g2) * b);

    // 4. Compute the pairing in two different ways to verify bilinearity.

    // First way: e([a]P, [b]Q)
    let pairing1 = pairing(&ap, &bq);

    // Second way: e(P, Q)^(a*b)
    let scalar_prod = a * b;
    let pairing2 = pairing(&p_g1, &q_g2) * scalar_prod;

    // 5. The results must be equal.
    assert_eq!(pairing1, pairing2);

    println!("Bilinearity property verified successfully!");
    println!("e([a]P, [b]Q) = {:?}", pairing1);
    println!("e(P, Q)^(a*b)  = {:?}", pairing2);
}
```

## Module Structure

The implementation is organized into several key modules:

*   `field/`: Contains the tower of finite fields (Fp, Fp2, Fp6, Fp12) that underpin the curve arithmetic.
*   `g1.rs`: Implements the G₁ group, including point representations and arithmetic.
*   `g2.rs`: Implements the G₂ group, including point representations and arithmetic.
*   `scalar.rs`: Implements arithmetic for the scalar field Fₙ.
*   `pairings.rs`: Implements the Miller loop, final exponentiation, and the top-level `pairing` and `multi_miller_loop` functions.
*   `tests/`: Contains unit and integration tests verifying the correctness of the field arithmetic, group operations, and pairing properties against known test vectors.