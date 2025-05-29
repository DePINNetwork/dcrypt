# Traditional Digital Signatures (`sign/traditional`)

This module within the `sign` crate focuses on implementations of well-established, classical (i.e., pre-quantum) digital signature algorithms. These algorithms have a long history of use and analysis and form the backbone of much of today's secure communication infrastructure.

**Note on Current Status:** While the ECDSA implementations (P-256, P-384, P-521) are detailed, other traditional signature schemes listed (Ed25519, RSA, DSA) are currently placeholders in the provided codebase snapshot. They define the necessary structs for keys and signatures and implement the `api::Signature` trait with dummy logic. This documentation describes their intended functionality and current status.

## Implemented/Planned Traditional Signature Schemes

1.  **EdDSA (Edwards-curve Digital Signature Algorithm)**
    *   **`Ed25519` (`eddsa`)**:
        *   **Description**: EdDSA signature scheme using Curve25519. Known for its high performance, small key/signature sizes, and resistance to certain side-channel attacks. It features deterministic nonce generation.
        *   **Standard**: RFC 8032.
        *   **Parameters**: Defined in `dcrypt-params/src/traditional/ed25519.rs`.
        *   **Files**: `dcrypt_docs/sign/traditional/eddsa/README.md` (covering `common.rs`, `main.rs`).
        *   **Status**: Placeholder implementation in `main.rs`.

2.  **ECDSA (Elliptic Curve Digital Signature Algorithm) (`ecdsa`)**
    *   **Description**: A widely adopted digital signature algorithm based on elliptic curve cryptography. Its security relies on the hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP). Implementations use deterministic nonce generation (RFC 6979 + hedging).
    *   **Variants**:
        *   `EcdsaP256`: Uses the NIST P-256 (secp256r1) curve with SHA-256.
        *   `EcdsaP384`: Uses the NIST P-384 (secp384r1) curve with SHA-384.
        *   `EcdsaP521`: Uses the NIST P-521 (secp521r1) curve with SHA-512.
    *   **Parameters**: Curve parameters for P-256, P-384, and P-521 are defined in `dcrypt-params/src/traditional/ecdsa.rs`.
    *   **Status**: Implemented with details for P-256, P-384, and P-521.
    *   **Files**: `dcrypt_docs/sign/traditional/ecdsa/README.md` (with links to curve-specific READMEs).

3.  **RSA Signatures (`rsa`)**
    *   **Description**: Signature schemes based on the RSA public-key cryptosystem, whose security relies on the difficulty of factoring large integers.
    *   **Variants**:
        *   `RsaPss` (RSA Probabilistic Signature Scheme): Recommended for new RSA signature applications.
        *   `RsaPkcs1` (RSA Signature Scheme with Appendix - PKCS#1 v1.5): Older padding scheme.
    *   **Parameters**: Modulus sizes are defined in `dcrypt-params/src/traditional/rsa.rs`.
    *   **Status**: Placeholder implementations.

4.  **DSA (Digital Signature Algorithm) (`dsa`)**
    *   **Description**: An older U.S. government standard for digital signatures based on the discrete logarithm problem in finite fields.
    *   **Parameters**: Modulus and subgroup sizes are defined in `dcrypt-params/src/traditional/dsa.rs`.
    *   **Security Notes**: Requires careful generation of per-signature random numbers (`k`).
    *   **Status**: Placeholder implementation.

## Core Trait

All these traditional signature schemes are intended to implement the `api::Signature` trait, providing a consistent interface for key generation, signing, and verification.

## Security Considerations

-   **Random Number Generation**: Schemes like DSA and older ECDSA variants require a unique, unpredictable random number for each signature generation. Failure to do so can lead to private key recovery. EdDSA (like Ed25519) and the DCRYPT ECDSA implementations use deterministic nonce generation (RFC 6979) to mitigate this risk.
-   **Key Lengths/Curve Choice**: Use appropriate key lengths (for RSA, DSA) or standard, well-vetted curves (for ECDSA) to ensure adequate security.
-   **Hash Functions**: Most signature schemes (except "pure" ones) operate on a hash of the message. The security of the signature scheme also depends on the security of the hash function used.
-   **Side-Channel Resistance**: Implementations of elliptic curve scalar multiplication and modular exponentiation need to be resistant to side-channel attacks. DCRYPT's `algorithms` crate aims to provide such primitives.

This module, once fully fleshed out for all listed schemes, will provide a suite of battle-tested classical signature algorithms.