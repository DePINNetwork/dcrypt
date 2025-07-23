//! Shared constants for secp256k1 operations

/// Size of a secp256k1 scalar in bytes (32 bytes = 256 bits)
pub const K256_SCALAR_SIZE: usize = 32;

/// Size of a secp256k1 field element in bytes (32 bytes = 256 bits)
pub const K256_FIELD_ELEMENT_SIZE: usize = 32;

/// Size of an uncompressed secp256k1 point in bytes: format byte (0x04) + x-coordinate + y-coordinate
pub const K256_POINT_UNCOMPRESSED_SIZE: usize = 1 + 2 * K256_FIELD_ELEMENT_SIZE; // 65 bytes: 0x04 || x || y

/// Size of a compressed secp256k1 point in bytes: format byte (0x02/0x03) + x-coordinate
pub const K256_POINT_COMPRESSED_SIZE: usize = 1 + K256_FIELD_ELEMENT_SIZE; // 33 bytes: 0x02/0x03 || x

/// Size of the KDF output for secp256k1 ECDH-KEM shared secret derivation
pub const K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE: usize = 32;