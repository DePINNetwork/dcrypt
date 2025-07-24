# Constant-Time Implementation Policy

This document outlines our policy for ensuring cryptographic operations in dcrypt
are resistant to timing side-channel attacks.

## Requirements

1. **Secret-Independent Execution Time:**
   - All cryptographic operations MUST have execution times independent of secret values.
   - This includes keys, nonces, and any other secret parameters.

2. **No Secret-Dependent Branches:**
   - Code MUST NOT contain conditional branches (if/else, switch, etc.) that depend on secret data.
   - All such operations MUST be implemented using branchless arithmetic (e.g., masking).

3. **No Secret-Dependent Memory Access:**
   - Memory access patterns MUST NOT depend on secret data.
   - Table lookups with secret-derived indices MUST be avoided or mitigated.

4. **Constant-Time Comparisons:**
   - All comparisons involving secret data MUST use the `subtle` crate's constant-time functions.

5. **Error Handling:**
   - Error paths MUST NOT leak timing information about secret values.
   - Error messages MUST NOT include details about secret values.

## Implementation Guidelines

1. **GF(2^8) Arithmetic:**
   - Use the provided branchless implementations for all Galois Field operations.

2. **Authentication Tag Verification:**
   - Always use `subtle::ConstantTimeEq` for AEAD and MAC tag verification.

3. **S-Box Lookups:**
   - Prefer hardware acceleration (AES-NI) when available.
   - Consider bitsliced implementations for software implementations.
   - At minimum, implement prefetching to reduce cache timing variations.

4. **Testing:**
   - All cryptographic operations SHOULD have constant-time tests.
   - Use the dudect framework to validate constant-time behavior.

## Verification

All changes to cryptographic primitives MUST be reviewed for constant-time compliance
before being merged. The CI pipeline includes dudect tests to verify constant-time behavior.