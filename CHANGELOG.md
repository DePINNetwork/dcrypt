# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[0.9.0-beta.1]: https://github.com/DePINNetwork/dcrypt/releases/tag/v0.9.0-beta.1