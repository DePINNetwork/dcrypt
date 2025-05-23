//! Cryptographic primitives library with constant-time implementation
//!
//! This crate provides implementations of various cryptographic primitives
//! with a focus on constant-time operations and resistance to side-channel attacks.
//! The library is designed to be usable in both `std` and `no_std` environments.
//!
//! # Security Features
//!
//! This library implements comprehensive security patterns to protect sensitive
//! cryptographic material, including:
//!
//! - Secure memory handling with automatic zeroization
//! - Constant-time comparison operations
//! - Memory barrier utilities
//! - Secure operation patterns

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Error module and re-exports
pub mod error;
pub use error::{
    Error, Result,
    ResultExt, SecureErrorHandling,
    validate,
};

// Block cipher implementations
pub mod block;
pub use block::{Aes128, Aes192, Aes256, Cbc, Ctr};

// Hash function implementations
pub mod hash;
pub use hash::{
    Sha1, Sha224, Sha256, Sha384, Sha512,
    Sha3_224, Sha3_256, Sha3_384, Sha3_512,
    Shake128, Shake256, Blake2b, Blake2s,
};

// AEAD cipher implementations
#[cfg(feature = "alloc")]
pub mod aead;
#[cfg(feature = "alloc")]
pub use aead::{
    ChaCha20Poly1305, XChaCha20Poly1305, Gcm,
    ChaCha20Poly1305Cipher, AeadCipher,
};

// MAC implementations
pub mod mac;
pub use mac::{Hmac, Poly1305};

// Stream cipher implementations
pub mod stream;
pub use stream::chacha::chacha20::ChaCha20;

// KDF implementations
#[cfg(feature = "alloc")]
pub mod kdf;
#[cfg(feature = "alloc")]
pub use kdf::{
    Pbkdf2, Hkdf, Argon2,
    KeyDerivationFunction, PasswordHashFunction
};

// Elliptic Curve primitives
pub mod ec;
pub use ec::{
    // Re-export common EC types
    P256Point, P256Scalar,
    P384Point, P384Scalar,
    
    // Re-export curve-specific modules
    p256, p384
};

// Type system
pub mod types;
pub use types::{
    Nonce, Salt, Tag, Digest, SecretBytes,
    ByteSerializable, FixedSize, ConstantTimeEq,
    RandomGeneration, SecureZeroingType,
};

// Re-export security types from dcrypt-core
pub use common::security::{
    SecretBuffer, SecretVec, EphemeralSecret, ZeroizeGuard,
    SecureOperation, SecureCompare, SecureOperationExt,
    SecureOperationBuilder, barrier,
};

// Algorithm types and compatibility traits
pub use types::{
    // Algorithm marker types
    algorithms::{
        Aes128 as Aes128Algorithm,
        Aes256 as Aes256Algorithm,
        ChaCha20 as ChaCha20Algorithm,
        ChaCha20Poly1305 as ChaCha20Poly1305Algorithm,
        Ed25519 as Ed25519Algorithm,
        X25519 as X25519Algorithm,
    },
    
    // Key types
    key::{SymmetricKey, AsymmetricSecretKey, AsymmetricPublicKey},
    
    // Compatibility traits for specific algorithms
    nonce::{
        ChaCha20Compatible, XChaCha20Compatible,
        AesGcmCompatible, AesCtrCompatible,
    },
    salt::{
        HkdfCompatible, Pbkdf2Compatible, Argon2Compatible,
    },
    digest::{
        Sha256Compatible, Sha512Compatible, Blake2bCompatible,
    },
    tag::{
        Poly1305Compatible, HmacCompatible, GcmCompatible,
        ChaCha20Poly1305Compatible,
    },
};

// XOF implementations (if enabled)
#[cfg(feature = "xof")]
pub mod xof;
#[cfg(feature = "xof")]
pub use xof::{ExtendableOutputFunction, ShakeXof128, ShakeXof256, Blake3Xof};