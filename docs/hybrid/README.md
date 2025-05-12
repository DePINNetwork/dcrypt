# Hybrid Cryptography (`hybrid`)

The `hybrid` crate in the DCRYPT ecosystem provides implementations of hybrid cryptographic schemes. Hybrid schemes combine two or more different cryptographic algorithms, typically a traditional (classical) algorithm and a post-quantum (PQ) algorithm, to achieve security against both classical and quantum adversaries.

The goal is to provide resilience in a transitional period where quantum computers are not yet a widespread threat but their future possibility necessitates preparation. If the PQ algorithm is later broken but the traditional one remains secure, the hybrid scheme should still offer security against classical attackers. Conversely, if the traditional algorithm is broken by a quantum computer but the PQ one is sound, the scheme should still offer security against quantum attackers.

This crate builds upon the KEMs and signature schemes defined in the `dcrypt-kem` and `dcrypt-sign` crates, respectively.

## Key Concepts

-   **Combined Security**: Aims to be at least as secure as the stronger of its constituent algorithms against relevant adversaries.
-   **KEM Hybrids**: Combine shared secrets from two KEMs (e.g., ECDH + Kyber). The resulting shared secret is often a concatenation or KDF-derived combination of the individual shared secrets. Ciphertexts are typically concatenations of the individual ciphertexts.
-   **Signature Hybrids**: Combine signatures from two schemes (e.g., ECDSA + Dilithium). A message is signed by both, and verification requires both individual signatures to be valid. Public/secret keys are concatenations or structured combinations of the individual keys.

## Implemented Hybrid Schemes

### Key Encapsulation Mechanisms (`dcrypt_docs/hybrid/kem/README.md`)

-   **`EcdhKyberHybrid`**: Combines ECDH P-256 with Kyber-768.
    -   `HybridPublicKey`: Contains `EcdhP256::PublicKey` and `Kyber768::PublicKey`.
    -   `HybridSecretKey`: Contains `EcdhP256::SecretKey` and `Kyber768::SecretKey`.
    -   `HybridSharedSecret`: The shared secret is a combination (e.g., concatenation) of the ECDH and Kyber shared secrets.
    -   `HybridCiphertext`: Contains `EcdhP256::Ciphertext` and `Kyber768::Ciphertext`.
-   **`EcdhNtruHybrid`**: Combines ECDH P-384 with NTRU-HPS.
    -   Structured similarly to `EcdhKyberHybrid`, using the respective ECDH and NTRU types.
-   **`RsaKyberHybrid`**: Combines RSA-KEM-2048 with Kyber-768.
    -   Structured similarly, using RSA-KEM and Kyber types.

### Digital Signature Schemes (`dcrypt_docs/hybrid/sign/README.md`)

-   **`EcdsaDilithiumHybrid`**: Combines ECDSA P-384 with Dilithium3.
    -   `HybridPublicKey`: Contains `EcdsaP384::PublicKey` and `Dilithium3::PublicKey`.
    -   `HybridSecretKey`: Contains `EcdsaP384::SecretKey` and `Dilithium3::SecretKey`.
    -   `HybridSignature`: Contains `EcdsaP384::SignatureData` and `Dilithium3::SignatureData`.
-   **`RsaFalconHybrid`**: Combines RSA-PSS with Falcon-512.
    -   Structured similarly, using RSA-PSS and Falcon types.

**Note**: The underlying KEM and signature schemes (e.g., `EcdhP256`, `Kyber768`, `RsaPss`, `Dilithium3`) are expected to be implemented in the `dcrypt-kem` and `dcrypt-sign` crates. These are currently placeholders, so the hybrid schemes also function as structural examples.

## Traits

The hybrid schemes implement the core traits from `dcrypt-api`:
-   Hybrid KEMs implement `api::Kem`.
-   Hybrid Signatures implement `api::Signature`.

## Usage Example (Conceptual Hybrid KEM)

```rust
// This example is conceptual as the underlying KEMs might be placeholders.
use dcrypt_hybrid::kem::EcdhKyberHybrid; // Example hybrid KEM
use dcrypt_api::Kem as KemTrait; // The core KEM trait
use rand::rngs::OsRng;
use dcrypt_api::Result;

fn hybrid_kem_example() -> Result<()> {
    let mut rng = OsRng;

    // 1. Key Generation
    // The keypair will contain combined public and secret keys for ECDH and Kyber.
    let (hybrid_pk, hybrid_sk) = EcdhKyberHybrid::keypair(&mut rng)?;

    // 2. Encapsulation
    // This will perform encapsulation with both ECDH and Kyber using their respective
    // parts of the hybrid_pk. The resulting shared secret is a combination.
    let (hybrid_ciphertext, shared_secret1) =
        EcdhKyberHybrid::encapsulate(&mut rng, &hybrid_pk)?;

    // 3. Decapsulation
    // This will decapsulate using both ECDH and Kyber secret keys from hybrid_sk
    // and their respective parts of hybrid_ciphertext.
    let shared_secret2 =
        EcdhKyberHybrid::decapsulate(&hybrid_sk, &hybrid_ciphertext)?;

    // 4. Verification
    // The derived shared secrets should be identical.
    assert_eq!(shared_secret1.as_ref(), shared_secret2.as_ref());

    println!("EcdhKyberHybrid KEM operation successful!");
    Ok(())
}

// fn main() {
//     hybrid_kem_example().expect("Hybrid KEM example failed.");
// }
```

## Security Considerations

-   **Component Security**: The security of a hybrid scheme relies on the security of its underlying components. At least one component must remain secure for the hybrid scheme to offer protection against the corresponding class of attacker.
-   **Combination Method**: The method used to combine keys, ciphertexts, shared secrets, and signatures is crucial. Simple concatenation is common, but KDFs might be used to combine shared secrets for better entropy distribution.
-   **Parameter Choice**: The parameters chosen for the constituent traditional and PQC algorithms should offer comparable levels of classical security to avoid one becoming a significantly weaker link.
-   **Performance Overhead**: Hybrid schemes inevitably incur a performance cost (key sizes, ciphertext/signature sizes, computation time) due to using multiple algorithms. This trade-off must be acceptable for the application.

This `hybrid` crate aims to provide pre-vetted combinations of algorithms, simplifying the adoption of PQC-resistant cryptography.