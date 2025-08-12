# CRYSTALS-Kyber KEM

## CRYSTALS-Kyber: A NIST Standard for Post-Quantum KEM

This module provides a pure Rust implementation of the **CRYSTALS-Kyber** Key Encapsulation Mechanism (KEM), which was selected by the U.S. National Institute of Standards and Technology (NIST) as the primary standard for post-quantum public-key encryption and key establishment, now formally published as **FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)**.

Kyber is designed to be secure against attacks from both classical and future quantum computers. Its security is based on the hardness of solving learning with errors problems over module lattices (Module-LWE).

This implementation provides IND-CCA2 security by converting the core CPA-secure Public Key Encryption (PKE) scheme into a secure KEM using a variant of the **Fujisaki-Okamoto (FO) transform**. This process involves cryptographic hashing (SHA3-256 and SHA3-512) and re-encryption checks to protect against chosen-ciphertext attacks.

### Features

-   **NIST Standard:** Implements the algorithm selected for FIPS 203, ensuring forward-compatibility and adherence to federal standards.
-   **Quantum-Resistant:** Provides security against attacks from large-scale quantum computers, addressing the "harvest now, decrypt later" threat.
-   **IND-CCA2 Security:** Achieves the standard security notion for KEMs, protecting against active attackers.
-   **Three Security Levels:** Offers clear trade-offs between security, performance, and key/ciphertext sizes:
    -   `Kyber512`: NIST Security Level 1 (comparable to AES-128).
    -   `Kyber768`: NIST Security Level 3 (comparable to AES-192).
    -   `Kyber1024`: NIST Security Level 5 (comparable to AES-256).
-   **Type Safety:** Uses distinct, strongly-typed wrappers for public keys (`KyberPublicKey`), secret keys (`KyberSecretKey`), and ciphertexts (`KyberCiphertext`) to prevent accidental misuse.
-   **Secure Memory Handling:** All secret key and shared secret materials are held in `Zeroizing` wrappers that automatically wipe the data from memory when they go out of scope.

## Security Levels

The three variants of Kyber correspond to different NIST PQC security levels, offering a balance between security and performance/size.

| Struct Name | NIST Level | Comparable Symmetric Security | Public Key Size | Secret Key Size | Ciphertext Size |
|:---|:---|:---|:---|:---|:---|
| `Kyber512` | 1 | AES-128 | 800 bytes | 1632 bytes | 768 bytes |
| `Kyber768` | 3 | AES-192 | 1184 bytes | 2400 bytes | 1088 bytes |
| `Kyber1024`| 5 | AES-256 | 1568 bytes | 3168 bytes | 1568 bytes |

All variants produce a **32-byte shared secret**.

## How It Works

The Kyber KEM is built in two main layers:

1.  **CPA-Secure PKE (`cpa_pke.rs`)**: The core of Kyber is a Public Key Encryption scheme that is secure against Chosen-Plaintext Attacks (CPA).
    -   **Key Generation**: A secret key `s` (a vector of small polynomials) and an error vector `e` are generated. The public key `t` is computed as `t = A*s + e`, where `A` is a public matrix derived from a seed `rho`.
    -   **Encryption**: A message `m` is encrypted by generating an ephemeral secret `r` and computing `u = A^T*r + e1` and `v = t^T*r + e2 + m`, where `e1` and `e2` are fresh error polynomials. The ciphertext is `(u, v)`.
    -   **Decryption**: The recipient uses their secret key `s` to compute `m' = v - s^T*u`, which removes the masking terms and recovers the message `m`.

2.  **IND-CCA2 Secure KEM (`ind_cca.rs`)**: To achieve security against Chosen-Ciphertext Attacks (CCA2), the CPA scheme is transformed into a KEM using the Fujisaki-Okamoto transform.
    -   **Encapsulation**:
        1.  A random message `m` is generated.
        2.  `m` and the recipient's public key are hashed to derive a symmetric key `K_bar` and randomness `r`.
        3.  The CPA scheme encrypts `m` using this derived randomness `r`, producing a ciphertext `ct`.
        4.  The final shared secret `K` is derived by hashing `K_bar` and a hash of the ciphertext `ct`.
        5.  The function returns `(ct, K)`.
    -   **Decapsulation**:
        1.  The recipient uses their private key to decrypt the ciphertext `ct` and recover the original message `m'`.
        2.  The recipient re-runs the encapsulation steps: hashing `m'` to derive `K_bar'` and `r'`, and then re-encrypting `m'` with `r'` to get `ct'`.
        3.  The re-encrypted `ct'` is compared to the received `ct` in constant time. If they do not match, the decapsulation is invalid.
        4.  To prevent leaking information via errors, the KEM uses **implicit rejection**: if the check fails, it computes the shared secret using a pre-generated "fallback" value `s_fo` stored in the secret key. Otherwise, it uses the correctly derived `K_bar'`. This ensures that a valid shared secret is always returned, but only the correct one if the ciphertext was valid.

## Usage Example

All Kyber variants implement the `dcrypt::api::Kem` trait.

```rust
use dcrypt::api::Kem;
use dcrypt::kem::kyber::Kyber768; // Using Level 3 security
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Recipient generates a Kyber key pair.
    let (public_key, secret_key) = Kyber768::keypair(&mut rng)?;

    println!("Public Key Size: {} bytes", public_key.as_bytes().len());
    println!("Secret Key Size: {} bytes", secret_key.len());

    // 2. Sender receives the public key and encapsulates a shared secret.
    let (ciphertext, shared_secret_sender) = Kyber768::encapsulate(&mut rng, &public_key)?;

    println!("Ciphertext Size: {} bytes", ciphertext.len());
    println!("Shared Secret Size: {} bytes", shared_secret_sender.len());

    // 3. Sender transmits the ciphertext to the recipient.

    // 4. Recipient uses their secret key to decapsulate the ciphertext.
    let shared_secret_recipient = Kyber768::decapsulate(&secret_key, &ciphertext)?;

    // 5. Both parties now have the same 32-byte shared secret.
    assert_eq!(
        &*shared_secret_sender.to_bytes_zeroizing(),
        &*shared_secret_recipient.to_bytes_zeroizing()
    );

    println!("\nSuccessfully established a shared secret with Kyber-768!");

    Ok(())
}
```

## Security Notes

-   **Secret Key Management**: The `KyberSecretKey` struct contains highly sensitive material. It is designed to be zeroized on drop. Avoid cloning it unnecessarily and minimize its lifetime.
-   **Side-Channel Resistance**: This implementation relies on the underlying `dcrypt-algorithms` crate for constant-time polynomial operations where applicable, which is critical for preventing timing attacks.
-   **Randomness**: The security of Kyber, like all KEMs, depends on a cryptographically secure random number generator (CSPRNG). Always use a trusted source of randomness, such as `rand::rngs::OsRng`.