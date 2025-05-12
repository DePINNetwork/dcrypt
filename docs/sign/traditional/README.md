# Traditional Digital Signatures (`sign/traditional`)

This module within the `sign` crate focuses on implementations of well-established, classical (i.e., pre-quantum) digital signature algorithms. These algorithms have a long history of use and analysis.

**Note on Current Status:** Like other PQC-focused modules in the snapshot, many of these traditional signature scheme implementations are placeholders. They define the necessary structs for keys and signatures and implement the `api::Signature` trait with dummy logic. This documentation describes their intended functionality.

## Implemented/Planned Traditional Signature Schemes

1.  **Ed25519 (`ed25519`)**
    *   **Description**: An instance of the Edwards-curve Digital Signature Algorithm (EdDSA) using Curve25519. It's known for high performance, small key and signature sizes, and resistance to several common side-channel attacks found in other elliptic curve signature schemes.
    *   **Standard**: RFC 8032.
    *   **Parameters**: Defined in `dcrypt-params/src/traditional/ed25519.rs`.
    *   **Files**: `dcrypt_docs/sign/traditional/ed25519/README.md` (covering `common.rs`, `main.rs`).
    *   **Status**: Placeholder implementation in `main.rs`.

2.  **ECDSA (Elliptic Curve Digital Signature Algorithm) (`ecdsa`)**
    *   **Description**: A widely adopted digital signature algorithm based on elliptic curve cryptography. Its security relies on the hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP).
    *   **Variants**:
        *   `EcdsaP256`: Uses the NIST P-256 (secp256r1) curve.
        *   `EcdsaP384`: Uses the NIST P-384 (secp384r1) curve.
    *   **Parameters**: Curve parameters for P-256 and P-384 are defined in `dcrypt-params/src/traditional/ecdsa.rs`.
    *   **Status**: Placeholder implementations.

3.  **RSA Signatures (`rsa`)**
    *   **Description**: Signature schemes based on the RSA public-key cryptosystem, whose security relies on the difficulty of factoring large integers.
    *   **Variants**:
        *   `RsaPss` (RSA Probabilistic Signature Scheme): Incorporates randomization and is generally recommended for new RSA signature applications due to stronger security proofs (e.g., against existential forgery under adaptive chosen-message attacks, assuming the underlying hash is secure and RSA problem is hard). Based on RSASSA-PSS from PKCS#1 v2.1/v2.2.
        *   `RsaPkcs1` (RSA Signature Scheme with Appendix - PKCS#1 v1.5): An older RSA signature padding scheme. While widely deployed, it has known theoretical weaknesses compared to PSS, though still considered secure if implemented correctly with strong hash functions.
    *   **Parameters**: Modulus sizes (e.g., 2048, 3072, 4096 bits) are defined in `dcrypt-params/src/traditional/rsa.rs`.
    *   **Status**: Placeholder implementations.

4.  **DSA (Digital Signature Algorithm) (`dsa`)**
    *   **Description**: An older U.S. government standard for digital signatures. Its security relies on the hardness of the discrete logarithm problem in a prime-order subgroup of Z_p^*.
    *   **Parameters**: Modulus and subgroup sizes (e.g., L=2048, N=256) are defined in `dcrypt-params/src/traditional/dsa.rs`.
    *   **Security Notes**: Less common in new applications compared to ECDSA or EdDSA. Requires careful generation of per-signature random numbers (`k`) to avoid key leakage.
    *   **Status**: Placeholder implementation.

## Core Trait

All these traditional signature schemes are intended to implement the `api::Signature` trait, providing a consistent interface for key generation, signing, and verification.

## Security Considerations

-   **Random Number Generation**: Schemes like DSA and ECDSA require a unique, unpredictable random number for each signature generation. Failure to do so can lead to private key recovery. EdDSA (like Ed25519) often uses deterministic nonce generation from the message and secret key to mitigate this risk.
-   **Key Lengths/Curve Choice**: Use appropriate key lengths (for RSA, DSA) or standard, well-vetted curves (for ECDSA) to ensure adequate security.
-   **Hash Functions**: Most signature schemes (except "pure" ones like some variants of Schnorr) operate on a hash of the message, not the message itself. The security of the signature scheme also depends on the security of the hash function used (e.g., SHA-256 or stronger).
-   **Side-Channel Resistance**: Implementations of elliptic curve scalar multiplication and modular exponentiation need to be resistant to side-channel attacks.

This module, once fully fleshed out, will provide a suite of battle-tested classical signature algorithms.