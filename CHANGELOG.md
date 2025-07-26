# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0-beta.1] - 2025-07-26

### Changed
- **BREAKING**: Removed version constant from ECDH-KEM KDF info parameter
  - KDF info strings no longer include version information
  - Changed from `"ECDH-{curve}-KEM {version}"` to `"ECDH-{curve}-KEM"`
  - Affects all ECDH implementations: B-283k, K-256, P-192, P-224, P-256, P-384, P-521
  - **This makes the KEM output incompatible with previous versions**
  - All systems using ECDH-KEM must be updated together as old and new versions cannot interoperate

### Removed
- `KEM_KDF_VERSION` constant from ECDH module
  - Version management now handled exclusively through Cargo dependencies

## [0.9.0-beta.3] - 2025-07-25

### Fixed
- **BREAKING**: Fixed `full` feature to include all crate dependencies
  - Added missing features: `algorithms`, `symmetric`, `kem`, `sign`, `pke`
  - Users enabling `full` now get access to all dcrypt modules as expected
  - Previously, modules like `dcrypt::sign` and `dcrypt::kem` were not available even with `full` feature

### Changed
- The `full` feature now properly includes all functionality:
  - Traditional cryptographic algorithms
  - Post-quantum algorithms
  - Hybrid constructions
  - All algorithm implementations (sign, kem, pke, symmetric)

## [0.9.0-beta.2] - 2025-07-25

### Changed
- **BREAKING**: Hardened signature API to prevent secret key corruption
  - Removed `AsMut<[u8]>` from all signature secret key types (Dilithium, ECDSA, Ed25519)
  - Redesigned signature traits to prevent direct byte access to secret keys
  - Split Signature trait into core + optional extension traits:
    - `SignatureSerialize`: Safe import/export with Zeroizing
    - `SignatureDerive`: Deterministic key derivation
    - `SignatureMessageLimits`: Algorithm constraints
    - `SignatureBatchVerify`: Efficient batch operations

### Security
- Prevented accidental corruption of secret key material by removing direct mutation ability
- Keys can now only be accessed through safe, validated methods that maintain invariants
- Affected algorithms must use explicit serialization methods rather than AsRef/AsMut

### Removed
- Release automation scripts (moved to separate tooling)

## [0.9.0-beta.1] - 2025-07-24

### Added
- Initial beta release of dcrypt
- Traditional cryptographic algorithms (AES, SHA-2, SHA-3, ECDSA, etc.)
- Post-quantum algorithms (Kyber, Dilithium)
- Hybrid cryptography support combining traditional and post-quantum
- Comprehensive test suite with ACVP test vectors
- no_std support for embedded systems
- Modular architecture with separate crates for different components
- Constant-time implementations for sensitive operations
- Automatic memory zeroization for sensitive data

### Security
- This is a beta release and has not been independently audited
- Not recommended for production use yet
- Seeking community feedback on API design and implementation

[Unreleased]: https://github.com/DePINNetwork/dcrypt/compare/v0.10.0-beta.1...HEAD
[0.10.0-beta.1]: https://github.com/DePINNetwork/dcrypt/compare/v0.9.0-beta.3...v0.10.0-beta.1
[0.9.0-beta.3]: https://github.com/DePINNetwork/dcrypt/compare/v0.9.0-beta.2...v0.9.0-beta.3
[0.9.0-beta.2]: https://github.com/DePINNetwork/dcrypt/compare/v0.9.0-beta.1...v0.9.0-beta.2
[0.9.0-beta.1]: https://github.com/DePINNetwork/dcrypt/releases/tag/v0.9.0-beta.1