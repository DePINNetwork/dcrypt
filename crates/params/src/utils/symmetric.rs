//! Constants for symmetric encryption algorithms

/// AES-128 key size in bytes
pub const AES128_KEY_SIZE: usize = 16;

/// AES-192 key size in bytes
pub const AES192_KEY_SIZE: usize = 24;

/// AES-256 key size in bytes
pub const AES256_KEY_SIZE: usize = 32;

/// AES block size in bytes
pub const AES_BLOCK_SIZE: usize = 16;

/// ChaCha20 key size in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// ChaCha20 block size in bytes
pub const CHACHA20_BLOCK_SIZE: usize = 64;

/// Poly1305 key size in bytes
pub const POLY1305_KEY_SIZE: usize = 32;

/// Poly1305 tag size in bytes
pub const POLY1305_TAG_SIZE: usize = 16;
