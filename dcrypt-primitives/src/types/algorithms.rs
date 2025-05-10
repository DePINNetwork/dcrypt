//! Algorithm definitions for type-safe cryptography
//!
//! This module defines concrete algorithm types that can be used
//! with the type-safe wrappers in this crate.

use crate::types::key::{SymmetricAlgorithm, AsymmetricAlgorithm};

// =============================================================================
// Symmetric Algorithms
// =============================================================================

/// AES-128 algorithm
pub enum Aes128 {}

impl SymmetricAlgorithm for Aes128 {
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;
    const ALGORITHM_ID: &'static str = "AES-128";
    
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// AES-256 algorithm
pub enum Aes256 {}

impl SymmetricAlgorithm for Aes256 {
    const KEY_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 16;
    const ALGORITHM_ID: &'static str = "AES-256";
    
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// ChaCha20 algorithm
pub enum ChaCha20 {}

impl SymmetricAlgorithm for ChaCha20 {
    const KEY_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    const ALGORITHM_ID: &'static str = "ChaCha20";
    
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// ChaCha20Poly1305 algorithm
pub enum ChaCha20Poly1305 {}

impl SymmetricAlgorithm for ChaCha20Poly1305 {
    const KEY_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    const ALGORITHM_ID: &'static str = "ChaCha20Poly1305";
    
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

// =============================================================================
// Asymmetric Algorithms
// =============================================================================

/// Ed25519 signature algorithm
pub enum Ed25519 {}

impl AsymmetricAlgorithm for Ed25519 {
    const PUBLIC_KEY_SIZE: usize = 32;
    const SECRET_KEY_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "Ed25519";
    
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// X25519 key exchange algorithm
pub enum X25519 {}

impl AsymmetricAlgorithm for X25519 {
    const PUBLIC_KEY_SIZE: usize = 32;
    const SECRET_KEY_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "X25519";
    
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

// Re-export type aliases for common key types
use crate::types::key::{SymmetricKey, AsymmetricSecretKey, AsymmetricPublicKey};

// Type aliases with explicit size parameters
/// AES-128 symmetric key (128-bit/16-byte key size).
pub type Aes128Key = SymmetricKey<Aes128, 16>;

/// AES-256 symmetric key (256-bit/32-byte key size).
pub type Aes256Key = SymmetricKey<Aes256, 32>;

/// ChaCha20 symmetric key (256-bit/32-byte key size).
pub type ChaCha20Key = SymmetricKey<ChaCha20, 32>;

/// ChaCha20-Poly1305 AEAD symmetric key (256-bit/32-byte key size).
pub type ChaCha20Poly1305Key = SymmetricKey<ChaCha20Poly1305, 32>;

// Asymmetric key aliases
/// Ed25519 secret key for digital signatures (256-bit/32-byte key size).
pub type Ed25519SecretKey = AsymmetricSecretKey<Ed25519, 32>;

/// Ed25519 public key for digital signatures (256-bit/32-byte key size).
pub type Ed25519PublicKey = AsymmetricPublicKey<Ed25519, 32>;

/// X25519 secret key for key exchange (256-bit/32-byte key size).
pub type X25519SecretKey = AsymmetricSecretKey<X25519, 32>;

/// X25519 public key for key exchange (256-bit/32-byte key size).
pub type X25519PublicKey = AsymmetricPublicKey<X25519, 32>;