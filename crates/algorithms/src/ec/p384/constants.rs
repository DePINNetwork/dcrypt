//! Shared constants and helper functions for P-384 operations

/// Size of a P-384 scalar in bytes (48 bytes = 384 bits)
pub const P384_SCALAR_SIZE: usize = 48;

/// Size of a P-384 field element in bytes (48 bytes = 384 bits)
pub const P384_FIELD_ELEMENT_SIZE: usize = 48;

/// Size of an uncompressed P-384 point in bytes: format byte (0x04) + x-coordinate + y-coordinate
pub const P384_POINT_UNCOMPRESSED_SIZE: usize = 1 + 2 * P384_FIELD_ELEMENT_SIZE; // 97 bytes: 0x04 || x || y

/// Size of a compressed P-384 point in bytes: format byte (0x02/0x03) + x-coordinate
pub const P384_POINT_COMPRESSED_SIZE: usize = 1 + P384_FIELD_ELEMENT_SIZE; // 49 bytes: 0x02/0x03 || x

/// Size of the KDF output for P-384 ECDH-KEM shared secret derivation
pub const P384_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE: usize = 48;
