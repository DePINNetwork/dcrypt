
---

### `sign` Crate Documentation Updates

#### **COMPLETE FILE:** `docs/sign/traditional/ecdsa/p256/README.md`
```markdown
# ECDSA with NIST P-256 (`sign::traditional::ecdsa::p256`)

This module implements the Elliptic Curve Digital Signature Algorithm (ECDSA) using the NIST P-256 curve (also known as secp256r1 or prime256v1). The implementation adheres to FIPS 186-4 for the core algorithm and incorporates deterministic nonce generation as per RFC 6979, hedged with additional entropy (inspired by FIPS 186-5 recommendations) for enhanced security against weak RNGs. SHA-256 is used as the hash function, as specified for P-256 in FIPS 186-4/5.

## Algorithm Details (`EcdsaP256`)

The `EcdsaP256` struct implements the `api::Signature` trait.

### Key Types

-   **`EcdsaP256PublicKey`**:
    *   Wraps a `[u8; algorithms::ec::p256::P256_POINT_UNCOMPRESSED_SIZE]`.
    *   Stores the P-256 public key point in uncompressed format (65 bytes: `0x04 || X-coordinate || Y-coordinate`).
-   **`EcdsaP256SecretKey`**:
    *   Contains `raw: algorithms::ec::p256::Scalar` and `bytes: [u8; algorithms::ec::p256::P256_SCALAR_SIZE]`.
    *   Stores the P-256 private key scalar (32 bytes) and its direct byte representation.
    *   Implements `Zeroize` and `Drop` for secure memory handling of the byte array component.

### Signature Format

-   **`EcdsaP256Signature`**:
    *   Wraps a `Vec<u8>`.
    *   Stores the ECDSA signature `(r, s)` encoded in ASN.1 DER format: `SEQUENCE { r INTEGER, s INTEGER }`.
    *   The integers `r` and `s` are derived from P-256 scalar values.

### Operations

1.  **`keypair(rng)`**:
    *   Generates a P-256 key pair using `algorithms::ec::p256::generate_keypair`.
    *   The private key scalar `d` is ensured to be in the range `[1, n-1]`, where `n` is the order of the curve's base point.
    *   The public key point `Q = d*G` is serialized in uncompressed format.

2.  **`sign(message, secret_key)`**:
    *   Hashes the input `message` using SHA-256.
    *   Converts the hash output to an integer `z` (specifically, the leftmost `min(N, bitlen(hash))` bits, where `N` for P-256 is 256 bits).
    *   Generates a per-message secret number `k` using deterministic nonce generation as per RFC 6979, hedged with additional entropy from a CSPRNG. HMAC-SHA256 is used as the PRF within RFC 6979.
    *   Computes the elliptic curve point `(x_1, y_1) = k*G`.
    *   Calculates `r = x_1 mod n`. If `r = 0`, a new `k` is generated and the process repeats.
    *   Calculates `s = k^(-1) * (z + r*d) mod n`. If `s = 0`, a new `k` is generated. (`d` is the private key scalar).
    *   The signature is the pair `(r, s)`, DER-encoded using the `SignatureComponents` helper.

3.  **`verify(message, signature, public_key)`**:
    *   Parses the DER-encoded `signature` (using `SignatureComponents::from_der`) to retrieve `r` and `s`. Validates that `r` and `s` are in the range `[1, n-1]`.
    *   Hashes the input `message` using SHA-256 to get `z`.
    *   Computes `w = s^(-1) mod n`.
    *   Computes `u1 = z*w mod n` and `u2 = r*w mod n`.
    *   Deserializes the `public_key` to point `Q`.
    *   Computes the point `(x_1, y_1) = u1*G + u2*Q`.
    *   If `(x_1, y_1)` is the point at infinity, the signature is invalid.
    *   Calculates `v = x_1 mod n`.
    *   The signature is valid if and only if `v == r`. Comparison is done in constant time.

This implementation provides a standard and secure digital signature scheme based on the P-256 curve.