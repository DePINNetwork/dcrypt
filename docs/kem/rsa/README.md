# RSA-KEM (`kem/rsa`)

This module is intended to implement Key Encapsulation Mechanisms (KEMs) based on the RSA public-key cryptosystem. RSA-KEM is a method for using RSA to securely establish a shared secret, often as specified in standards like IEEE 1363a-2004 or ISO/IEC 18033-2.

**Note on Current Status:** The implementations in the provided codebase snapshot (`rsa/*.rs`) are placeholders. They define the necessary structs for different RSA modulus sizes (`RsaKem2048`, `RsaKem4096`) and implement the `api::Kem` trait with dummy logic. This documentation describes the intended functionality based on this structure and common RSA-KEM practices.

## RSA-KEM Overview

RSA-KEM leverages the RSA trapdoor permutation.
-   **Key Generation**: Standard RSA key generation produces a public key `(n, e)` and a private key `(n, d)`, where `n` is the modulus and `e, d` are the public and private exponents, respectively.
-   **Encapsulation (Sender)**:
    1.  Generate a random value `x` in the range `[0, n-1)`.
    2.  Compute the ciphertext `c = x^e mod n`. This `c` is the KEM ciphertext.
    3.  The shared secret `K` is derived from `x` using a Key Derivation Function (KDF): `K = KDF(x)`.
-   **Decapsulation (Recipient)**:
    1.  Receives `c`.
    2.  Computes `x = c^d mod n`.
    3.  Derives the shared secret `K` using the same KDF: `K = KDF(x)`.

## Implemented Variants (Placeholders)

1.  **`RsaKem2048` (`rsa2048.rs`)**:
    *   Intended to use a 2048-bit RSA modulus (`n`).
    *   **`RsaPublicKey`**: Contains `modulus: Vec<u8>` (256 bytes) and `exponent: Vec<u8>` (typically 3 bytes for 65537).
    *   **`RsaSecretKey`**: Contains `modulus: Vec<u8>` and `private_exponent: Vec<u8>` (256 bytes).
    *   **`RsaSharedSecret(api::Key)`**: Wrapper for the derived shared secret (placeholder uses 32 bytes).
    *   **`RsaCiphertext(Vec<u8>)`**: Wrapper for the ciphertext `c` (256 bytes).

2.  **`RsaKem4096` (`rsa4096.rs`)**:
    *   Intended to use a 4096-bit RSA modulus (`n`).
    *   The file `rsa4096.rs` is noted as "Similar implementation as rsa2048.rs with appropriate parameter changes." This implies a 512-byte modulus and private exponent.
    *   Structure is `RsaKemBase<512>` (though the snapshot uses `<4096>` in the type alias, the internal logic would handle byte sizes).

## Core Components (`common.rs`)

-   **`RsaKemBase<const MODULUS_SIZE: usize>`**: A generic base struct intended to be parameterized by the RSA modulus size in *bits*.
-   **`RsaPublicKey`**, **`RsaSecretKey`**, **`RsaSharedSecret`**, **`RsaCiphertext`**: Structs as described above. `RsaPublicKey` and `RsaSecretKey` implement `Zeroize`.

## `api::Kem` Trait Implementation

Each RSA-KEM variant (e.g., `RsaKem2048`) implements the `api::Kem` trait:

-   `name()`: Returns the specific variant name (e.g., "RSA-2048").
-   `keypair()`:
    *   **Placeholder Logic**: Generates random byte vectors for the modulus and private exponent. The public exponent is commonly fixed to 65537 (0x010001). Includes placeholder validation.
-   `public_key()`: Extracts the `RsaPublicKey` from the keypair.
-   `secret_key()`: Extracts the `RsaSecretKey` from the keypair.
-   `encapsulate()`:
    *   Validates public key components (modulus and exponent lengths, non-zero content).
    *   **Placeholder Logic**: Generates random byte vectors for the ciphertext (size of modulus) and a 32-byte shared secret.
-   `decapsulate()`:
    *   Validates secret key components and ciphertext lengths and non-zero content.
    *   **Placeholder Logic**: Returns a dummy zero-filled 32-byte shared secret.

## Security Considerations (General for RSA-KEM)

-   **RSA Key Generation**: Secure generation of large prime numbers for RSA is critical. Weak primes can lead to factorization of the modulus `n`.
-   **Padding/KDF**: RSA-KEM itself (as described above, sometimes called "raw" RSA KEM) does not inherently provide IND-CCA2 security. Schemes like RSA-KEM from IEEE 1363a or ISO/IEC 18033-2 often incorporate specific KDFs and padding/formatting for `x` to achieve stronger security guarantees. For example, `x` might be padded before exponentiation.
-   **KDF Choice**: The KDF used to derive the shared secret `K` from `x` must be cryptographically secure (e.g., HKDF).
-   **Modulus Size**: The security of RSA depends on the size of the modulus `n`. 2048 bits is a common minimum today, with 3072 or 4096 bits recommended for longer-term security.
-   **Side-Channel Attacks**: RSA private key operations (modular exponentiation with `d`) can be vulnerable to side-channel attacks if not implemented carefully (e.g., using blinding).

This module, once fully implemented with proper RSA operations and a secure KDF, would provide a classical KEM based on the widely understood RSA problem.