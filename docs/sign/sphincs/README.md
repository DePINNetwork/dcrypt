# SPHINCS+ Digital Signature Algorithm (`sign/sphincs`)

This module is intended to implement the SPHINCS+ digital signature algorithm. SPHINCS+ is a stateless hash-based signature scheme, meaning its security relies solely on the properties of the underlying hash functions and it does not require keeping state between signatures (unlike stateful hash-based signatures like LMS/XMSS). It was selected by NIST for standardization in the Post-Quantum Cryptography (PQC) project.

SPHINCS+ is known for its strong security assumptions (minimal, relying on hash function properties) but typically has larger signature sizes and slower performance compared to lattice-based or code-based PQC schemes.

**Note on Current Status:** The implementation in the provided codebase snapshot (`sphincs/mod.rs`) is a placeholder. It defines the necessary structs for SPHINCS+ variants (based on SHA-2 or SHAKE) and implements the `api::Signature` trait with dummy logic. This documentation describes the intended functionality based on this structure and SPHINCS+ specifications.

## SPHINCS+ Variants

SPHINCS+ can be instantiated with different hash functions and parameter sets. The module outlines support for:

1.  **`SphincsSha2`**:
    *   Intended to use SHA-256 as the primary hash function and Haraka for short-input hashing within the WOTS+ and FORS components.
    *   Specific parameter sets like SPHINCS+-SHA256-128s, SPHINCS+-SHA256-128f, etc., (defined in `dcrypt-params/src/pqc/sphincs.rs`) would determine the exact configuration (hypertree height `h`, layers `d`, Winternitz `w`, FORS `k`, `t`).
    *   Example sizes (for 128s): PK=32B, SK=64B, Sig=7856B.

2.  **`SphincsShake`**:
    *   Intended to use SHAKE256 as the primary hash function and Haraka.
    *   Similar parameter set variations as `SphincsSha2`.
    *   Example sizes (for 128s, assuming SHAKE gives similar hash output sizes for internal nodes): PK=32B, SK=64B, Sig=7856B.

## Core Components and Types

-   **`SphincsPublicKey(Vec<u8>)`**: Wrapper for SPHINCS+ public keys (typically `PK.seed` and `PK.root`). Implements `Zeroize`.
-   **`SphincsSecretKey(Vec<u8>)`**: Wrapper for SPHINCS+ secret keys (typically `SK.seed`, `SK.prf`, `PK.seed`, `PK.root`). Implements `Zeroize`.
-   **`SphincsSignature(Vec<u8>)`**: Wrapper for SPHINCS+ signatures (a complex structure containing a FORS signature, WOTS+ signatures for an authentication path in a hypertree, and potentially randomness).

## `api::Signature` Trait Implementation

Each SPHINCS+ variant (`SphincsSha2`, `SphincsShake`) implements the `api::Signature` trait:

-   `name()`: Returns the specific variant name (e.g., "SPHINCS+-SHA2").
-   `keypair()`:
    *   **Placeholder Logic**: Fills byte vectors with random data for public and secret keys according to example sizes (e.g., 32B PK, 64B SK).
-   `public_key()`: Extracts the `SphincsPublicKey` from the keypair.
-   `secret_key()`: Extracts the `SphincsSecretKey` from the keypair.
-   `sign()`:
    *   **Placeholder Logic**: Returns a dummy signature `SphincsSignature` filled with zeros, with a size appropriate for an example variant (e.g., SPHINCS+-SHA256-128f or SPHINCS+-SHAKE-128s).
-   `verify()`:
    *   **Placeholder Logic**: Always returns `Ok(())`, indicating successful verification.

## Security Basis

SPHINCS+ security relies on the properties of the underlying cryptographic hash functions:
-   **WOTS+ (Winternitz One-Time Signature)**: Relies on second pre-image resistance.
-   **FORS (Forest of Random Subsets)**: A few-time signature scheme, relies on second pre-image resistance.
-   **Merkle Tree Scheme**: The hypertree structure relies on collision resistance for constructing the tree and second pre-image resistance for authentication paths.

Because it's stateless, it doesn't suffer from the "state management" problem of earlier hash-based signatures if a key is used to sign multiple messages.

## Intended Functionality (Once Fully Implemented)

SPHINCS+ is a complex construction involving several layers:

-   **WOTS+ (Winternitz One-Time Signatures)**: Used as the leaves of Merkle trees. A WOTS+ key pair is used to sign a single message digest.
-   **Hypertree**: A tree of Merkle trees.
    -   At the bottom layer (layer 0), many WOTS+ key pairs are generated. Their public keys form the leaves of Merkle trees. The roots of these Merkle trees become leaves for Merkle trees at the next layer up, and so on.
    -   The final root of the top-most Merkle tree is part of the SPHINCS+ public key.
-   **FORS (Forest of Random Subsets)**: A few-time signature scheme used to sign the root of a selected Merkle tree from the hypertree (or a digest derived from it and the message). A FORS key pair is selected based on a message-derived index.
-   **Key Generation**:
    1.  Generate a secret seed `SK.seed` and a PRF key `SK.prf`.
    2.  Generate `PK.seed` for public pseudorandomness.
    3.  Use these to deterministically generate the entire SPHINCS+ structure, culminating in `PK.root`.
    4.  The public key is `(PK.seed, PK.root)`. The secret key is `(SK.seed, SK.prf, PK.seed, PK.root)`.
-   **Signing**:
    1.  Hash the message `M`, potentially with randomness `R`, to get a digest `D`.
    2.  Use `D` to select a FORS key pair and an index `idx` for a leaf in the hypertree.
    3.  Sign `D` with the selected FORS private key to get `SIG_FORS`.
    4.  The public key of this FORS instance is then signed by a WOTS+ key pair corresponding to the leaf `idx` at the bottom layer of the hypertree. This produces `SIG_WOTS_0` and an authentication path `AUTH_0` for this WOTS+ public key up to its Merkle root.
    5.  This Merkle root is then a leaf in the layer 1 Merkle tree. Its authentication is signed by another WOTS+ key, `SIG_WOTS_1`, providing `AUTH_1`, and so on, up the hypertree.
    6.  The SPHINCS+ signature consists of `(R, SIG_FORS, SIG_WOTS_0, AUTH_0, ..., SIG_WOTS_{d-1}, AUTH_{d-1})`.
-   **Verification**:
    1.  Recompute the message digest `D` using `M` and `R` from the signature.
    2.  Use `D` to select the FORS public key. Verify `SIG_FORS` to get the FORS public key value.
    3.  This FORS public key value is the message for the first WOTS+ signature. Verify `SIG_WOTS_0` using this message and the WOTS+ public key derived from `AUTH_0` and `PK.seed`. This yields the Merkle root for the layer 0 tree.
    4.  Repeat this process: the Merkle root from layer `i` becomes the message for `SIG_WOTS_{i+1}`, which is verified using `AUTH_{i+1}`.
    5.  The final computed root of the top-most Merkle tree is compared with `PK.root` from the SPHINCS+ public key.

The placeholder structure provides the API for this complex, multi-layered signature scheme.