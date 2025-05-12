# Hybrid Digital Signatures (`hybrid/sign`)

This module implements hybrid digital signature schemes. Similar to hybrid KEMs, hybrid signature schemes combine a traditional (classical) signature algorithm with a post-quantum (PQ) signature algorithm. The goal is to produce a combined signature that is verifiable using combined public keys and remains secure as long as at least one of the constituent signature schemes is secure against the relevant class of attacks (classical or quantum).

## Implemented Hybrid Signature Schemes

1.  **`EcdsaDilithiumHybrid` (`ecdsa_dilithium.rs`)**:
    *   **Combines**: ECDSA P-384 (Elliptic Curve Digital Signature Algorithm over P-384) and Dilithium3 (a lattice-based PQC digital signature algorithm, NIST Level 3).
    *   **Purpose**: To provide signatures that are verifiable using both a classical and a post-quantum algorithm, offering resilience against future quantum threats while maintaining compatibility with existing classical infrastructure.
    *   **Key Structure**:
        *   `HybridPublicKey`: Contains an `EcdsaP384::PublicKey` and a `Dilithium3::PublicKey`.
        *   `HybridSecretKey`: Contains an `EcdsaP384::SecretKey` and a `Dilithium3::SecretKey`.
    *   **Operation**:
        *   `sign`: The message is signed independently by both ECDSA P-384 and Dilithium3 using their respective secret keys. The resulting `HybridSignature` contains both individual signatures.
        *   `verify`: To verify a `HybridSignature`, both the ECDSA signature and the Dilithium signature must be independently verified against the message using their respective public keys. Both must be valid for the hybrid signature to be considered valid.
    *   **Signature**: `HybridSignature` stores `EcdsaP384::SignatureData` and `Dilithium3::SignatureData`.

2.  **`RsaFalconHybrid` (`rsa_falcon.rs`)**:
    *   **Combines**: RSA-PSS (RSA Probabilistic Signature Scheme) and Falcon-512 (a lattice-based PQC digital signature algorithm, NIST Level 1).
    *   **Purpose**: Similar to `EcdsaDilithiumHybrid`, providing dual protection with different underlying cryptographic assumptions.
    *   **Structure and Operation**: Analogous to `EcdsaDilithiumHybrid`, but using RSA-PSS and Falcon-512 components.

## Common Structure

All hybrid signature schemes in this module adhere to a similar design:

-   Define `HybridPublicKey`, `HybridSecretKey`, and `HybridSignature` structs that encapsulate the corresponding components from the individual signature schemes.
-   Implement the `api::Signature` trait.
-   The `keypair` function generates keypairs for both underlying signature schemes and combines them into the hybrid keypair.
-   The `sign` method generates two separate signatures using the respective secret keys and packages them into the `HybridSignature` structure.
-   The `verify` method takes the `HybridSignature`, unpacks the individual signatures, and verifies each one using the corresponding public key. Both verifications must succeed for the overall hybrid verification to pass.

**Note**: The underlying signature schemes (e.g., `EcdsaP384`, `Dilithium3`, `RsaPss`, `Falcon512`) are expected to be implemented in the `dcrypt-sign` crate. The current code snapshot indicates these are placeholders. Consequently, these hybrid signature implementations are also structural placeholders, illustrating the construction methodology rather than being fully operational.

## Security Principle

For a hybrid signature, a message `M` is signed with the classical key `SK_c` to produce `Sig_c`, and with the post-quantum key `SK_pq` to produce `Sig_pq`. The hybrid signature is `(Sig_c, Sig_pq)`. Verification requires checking `Verify(PK_c, M, Sig_c)` AND `Verify(PK_pq, M, Sig_pq)`.

This construction ensures that:
-   If an attacker can only break the classical signature scheme, the post-quantum signature still protects the message's integrity and authenticity against quantum (and classical) adversaries.
-   If an attacker can only break the post-quantum signature scheme (perhaps due to an unforeseen flaw or a more powerful classical computer than anticipated for some PQC schemes), the classical signature still protects the message against classical adversaries.

The hybrid signature is considered valid only if both component signatures are valid. This provides a robust defense during the transition to post-quantum cryptography.