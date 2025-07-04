//! Shared constants and helper functions for P-256 operations

/// Size of a P-256 scalar in bytes (32 bytes = 256 bits)
pub const P256_SCALAR_SIZE: usize = 32;

/// Size of a P-256 field element in bytes (32 bytes = 256 bits)
pub const P256_FIELD_ELEMENT_SIZE: usize = 32;

/// Size of an uncompressed P-256 point in bytes: format byte (0x04) + x-coordinate + y-coordinate
pub const P256_POINT_UNCOMPRESSED_SIZE: usize = 1 + 2 * P256_FIELD_ELEMENT_SIZE; // 65 bytes: 0x04 || x || y

/// Size of a compressed P-256 point in bytes: format byte (0x02/0x03) + x-coordinate
pub const P256_POINT_COMPRESSED_SIZE: usize = 1 + P256_FIELD_ELEMENT_SIZE; // 33 bytes: 0x02/0x03 || x

/// Size of the KDF output for P-256 ECDH-KEM shared secret derivation
pub const P256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE: usize = 32;