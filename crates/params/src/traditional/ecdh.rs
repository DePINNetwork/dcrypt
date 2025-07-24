//! Constants for Elliptic Curve Diffie-Hellman

// We'll refer to the ECDSA parameters from the same curve, but not import them
// directly to avoid the unused import warning

/// Size of shared secret for ECDH using P-256 in bytes
pub const ECDH_P256_SHARED_SECRET_SIZE: usize = 32;

/// Size of shared secret for ECDH using P-384 in bytes
pub const ECDH_P384_SHARED_SECRET_SIZE: usize = 48;

/// Size of public key for ECDH using P-256 in bytes (uncompressed format)
pub const ECDH_P256_PUBLIC_KEY_SIZE: usize = 65;

/// Size of public key for ECDH using P-384 in bytes (uncompressed format)
pub const ECDH_P384_PUBLIC_KEY_SIZE: usize = 97;

/// Size of private key for ECDH using P-256 in bytes
pub const ECDH_P256_PRIVATE_KEY_SIZE: usize = 32;

/// Size of private key for ECDH using P-384 in bytes
pub const ECDH_P384_PRIVATE_KEY_SIZE: usize = 48;
