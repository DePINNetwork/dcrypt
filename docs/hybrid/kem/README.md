# Hybrid Key Encapsulation Mechanisms (`hybrid/kem`)

This module implements hybrid Key Encapsulation Mechanisms (KEMs). Hybrid KEMs combine a traditional (classical) KEM with a post-quantum (PQ) KEM to provide security against both classical and quantum adversaries. The goal is to achieve a combined shared secret that remains secure as long as at least one of the constituent KEMs is secure against the relevant type of attack.

## Implemented Hybrid KEMs

1.  **`EcdhKyberHybrid` (`ecdh_kyber.rs`)**:
    *   **Combines**: ECDH P-256 (Elliptic Curve Diffie-Hellman over the P-256 curve) and Kyber-768 (a lattice-based PQC KEM).
    *   **Purpose**: Provides security against classical attacks (via ECDH) and quantum attacks (via Kyber).
    *   **Key Structure**:
        *   `HybridPublicKey`: Contains an `EcdhP256::PublicKey` and a `Kyber768::PublicKey`.
        *   `HybridSecretKey`: Contains an `EcdhP256::SecretKey` and a `Kyber768::SecretKey`.
    *   **Operation**:
        *   `encapsulate`: Performs ECDH key agreement and Kyber encapsulation. The two resulting shared secrets are combined (e.g., concatenated) to form the final hybrid shared secret. The ciphertext is a combination of the ECDH ephemeral public key and the Kyber ciphertext.
        *   `decapsulate`: Performs ECDH key agreement with the received ephemeral public key and decapsulates the Kyber ciphertext. The two shared secrets are then combined in the same way as during encapsulation.
    *   **Shared Secret**: `HybridSharedSecret` wraps an `api::Key` containing the combined secret material.
    *   **Ciphertext**: `HybridCiphertext` stores the ciphertexts from both ECDH (typically the ephemeral public key) and Kyber.

2.  **`EcdhNtruHybrid` (`ecdh_ntru.rs`)**:
    *   **Combines**: ECDH P-384 and NTRU-HPS (NTRUEncrypt, a lattice-based PQC KEM).
    *   **Purpose**: Similar to `EcdhKyberHybrid`, offering dual protection.
    *   **Structure and Operation**: Analogous to `EcdhKyberHybrid`, but using ECDH P-384 and NTRU-HPS components.

3.  **`RsaKyberHybrid` (`rsa_kyber.rs`)**:
    *   **Combines**: RSA-KEM (e.g., RSA-KEM-2048, though the snapshot uses a generic `RsaKem2048` type) and Kyber-768.
    *   **Purpose**: Provides a hybrid based on the widely deployed RSA and the PQC candidate Kyber.
    *   **Structure and Operation**: Analogous to the ECDH-based hybrids, replacing ECDH with RSA-KEM.

## Common Structure

All hybrid KEMs in this module follow a similar pattern:

-   Define `HybridPublicKey`, `HybridSecretKey`, `HybridSharedSecret`, and `HybridCiphertext` structs that internally hold the corresponding components from the constituent KEMs.
-   Implement the `api::Kem` trait.
-   The `keypair` function generates keypairs for both underlying KEMs and combines them.
-   The `encapsulate` function performs encapsulation with both KEMs and combines their outputs (ciphertexts and shared secrets).
-   The `decapsulate` function performs decapsulation with both KEMs and combines the resulting shared secrets to reconstruct the hybrid shared secret.

**Note**: The provided code snapshot shows that the underlying KEMs (`EcdhP256`, `Kyber768`, `NtruHps`, `RsaKem2048`) in the `dcrypt-kem` crate are placeholders. Therefore, these hybrid KEM implementations are also structural placeholders demonstrating how such hybrids would be constructed, rather than fully functional cryptographic implementations.

## Security Principle

The fundamental idea is that the hybrid shared secret `SS_hybrid` is derived from the classical shared secret `SS_classical` and the post-quantum shared secret `SS_pq` (e.g., `SS_hybrid = KDF(SS_classical || SS_pq)`).
An attacker would need to break *both* the classical KEM and the post-quantum KEM to recover `SS_hybrid`.
- If only classical KEMs are vulnerable (e.g., to a quantum computer), `SS_pq` remains secure.
- If the PQ KEM has an unforeseen flaw but the classical KEM is secure against classical attackers, `SS_classical` remains secure.

This provides a transition strategy towards fully post-quantum cryptography.