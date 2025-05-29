# ECDSA Signature Implementations (`sign::traditional::ecdsa`)

This module provides secure implementations of the Elliptic Curve Digital Signature Algorithm (ECDSA) using various NIST standard curves. ECDSA is a widely adopted digital signature standard, and its security relies on the hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP).

All implementations adhere to FIPS 186-4/5 specifications and employ deterministic nonce generation as per RFC 6979, hedged with additional entropy (inspired by FIPS 186-5 recommendations) to enhance security against weak random number generators.

## Core Components and Helpers

-   **`common.rs`**: Contains shared utilities, primarily the `SignatureComponents` struct for handling the `(r, s)` integer pair of an ECDSA signature and methods for ASN.1 DER encoding/decoding of these components.
-   **Curve-Specific Modules**: Each supported NIST curve (P-256, P-384, P-521) has its own module implementing ECDSA tailored for that curve's parameters and recommended hash function.

## Implemented Variants

The DCRYPT library provides ECDSA implementations for the following NIST standard curves:

1.  **`EcdsaP256` (`p256`)**:
    *   **Curve**: NIST P-256 (secp256r1).
    *   **Hash Function**: SHA-256.
    *   **Key Sizes**: Public Key (uncompressed): 65 bytes; Secret Key: 32 bytes.
    *   **Signature Format**: ASN.1 DER encoded `(r, s)` pair.
    *   **Details**: Refer to `dcrypt_docs/sign/traditional/ecdsa/p256/README.md`.

2.  **`EcdsaP384` (`p384`)**:
    *   **Curve**: NIST P-384 (secp384r1).
    *   **Hash Function**: SHA-384.
    *   **Key Sizes**: Public Key (uncompressed): 97 bytes; Secret Key: 48 bytes.
    *   **Signature Format**: ASN.1 DER encoded `(r, s)` pair.
    *   **Details**: Refer to `dcrypt_docs/sign/traditional/ecdsa/p384/README.md`.

3.  **`EcdsaP521` (`p521`)**:
    *   **Curve**: NIST P-521 (secp521r1).
    *   **Hash Function**: SHA-512 (as per FIPS 186-5 recommendations for P-521).
    *   **Key Sizes**: Public Key (uncompressed): 133 bytes; Secret Key: 66 bytes.
    *   **Signature Format**: ASN.1 DER encoded `(r, s)` pair.
    *   **Details**: Refer to `dcrypt_docs/sign/traditional/ecdsa/p521/README.md`.

## `api::Signature` Trait Implementation

Each `EcdsaP*` struct implements the `api::Signature` trait, providing a consistent interface for:
-   Key pair generation (`keypair`).
-   Public and secret key extraction.
-   Message signing (`sign`).
-   Signature verification (`verify`).

## Security Considerations

-   **Deterministic Nonces (RFC 6979)**: The use of deterministic nonce generation (hedged with external randomness) mitigates a common class of vulnerabilities related to weak or repeated `k` values in ECDSA.
-   **Hash Function Strength**: The security of ECDSA is tied to the strength of the hash function used (SHA-256 for P-256, SHA-384 for P-384, SHA-512 for P-521).
-   **Scalar Operations**: All underlying elliptic curve scalar multiplications and modular arithmetic operations are performed using primitives from the `algorithms::ec` module, which are designed with constant-time execution in mind.
-   **Point Validation**: Public keys (elliptic curve points) are validated during operations like verification to ensure they lie on the specified curve.
-   **Signature Normalization**: While not explicitly detailed for these specific files, ECDSA implementations sometimes need to handle signature malleability (e.g., by ensuring `s` is in the lower half of the curve order). The use of standard test vectors would typically cover this.

This module aims to provide robust and secure implementations of ECDSA for commonly used NIST curves.