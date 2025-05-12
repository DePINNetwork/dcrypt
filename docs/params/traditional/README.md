# Traditional Cryptography Parameters (`params/traditional`)

This module within the `params` crate consolidates constants and parameters for well-established traditional (classical) cryptographic algorithms. These parameters are often derived from standards documents like NIST FIPS, RFCs, or SECG specifications.

## Traditional Algorithm Parameters

1.  **RSA (`rsa.rs`)**:
    *   Defines common RSA modulus sizes in bits: `RSA_MODULUS_2048`, `RSA_MODULUS_3072`, `RSA_MODULUS_4096`.
    *   Specifies the common RSA public exponent: `RSA_PUBLIC_EXPONENT` (65537).
    *   Provides byte lengths for keys corresponding to these modulus sizes: `RSA_2048_BYTE_LENGTH`, etc.

2.  **DSA (Digital Signature Algorithm) (`dsa.rs`)**:
    *   Defines common DSA parameter pairs (modulus size L, subgroup order size N): `DSA_2048_256`, `DSA_3072_256`.
    *   `DSA_SIGNATURE_SIZE`: The typical size of a DSA signature (concatenation of `r` and `s`).
    *   Byte lengths for modulus `P` and subgroup order `Q`.

3.  **DH (Diffie-Hellman) (`dh.rs`)**:
    *   Defines common DH modulus sizes: `DH_MODULUS_2048`, `DH_MODULUS_3072`, `DH_MODULUS_4096`.
    *   Byte lengths for keys corresponding to these modulus sizes.
    *   `DH_2048_GENERATOR`: The standard generator (2) for RFC 3526 MODP Group 14.
    *   `DH_2048_PRIME_HEAD`: First few bytes of the RFC 3526 MODP Group 14 prime, useful for quick identification or verification.

4.  **ECDSA (Elliptic Curve Digital Signature Algorithm) (`ecdsa.rs`)**:
    *   Defines parameter structures (`NistP256Params`, `NistP384Params`) for NIST standard curves P-256 and P-384.
    *   These structures include:
        *   Prime modulus `p`.
        *   Curve coefficients `a` and `b`.
        *   Generator point coordinates `g_x`, `g_y`.
        *   Order of the curve `n`.
        *   Cofactor `h`.
    *   Constants `NIST_P256` and `NIST_P384` provide instances of these parameter structures.

5.  **ECDH (Elliptic Curve Diffie-Hellman) (`ecdh.rs`)**:
    *   Defines key and shared secret sizes for ECDH using NIST P-256 and P-384 curves.
    *   Sizes include: `ECDH_P256_SHARED_SECRET_SIZE`, `ECDH_P256_PUBLIC_KEY_SIZE` (uncompressed), `ECDH_P256_PRIVATE_KEY_SIZE`, and similarly for P-384.
    *   These often align with the sizes derived from the ECDSA parameters for the same curves.

6.  **Ed25519 (`ed25519.rs`)**:
    *   Defines constants specific to the Ed25519 signature algorithm (based on Curve25519):
        *   `ED25519_PUBLIC_KEY_SIZE` (32 bytes)
        *   `ED25519_SECRET_KEY_SIZE` (32 bytes)
        *   `ED25519_SIGNATURE_SIZE` (64 bytes)
        *   `ED25519_CURVE_ORDER` (the order of the base point, little-endian)
        *   `ED25519_BASE_Y` (the y-coordinate of the Ed25519 base point)

These constants are fundamental for implementing and correctly using traditional cryptographic algorithms, ensuring that operations are performed with standard, vetted parameters.