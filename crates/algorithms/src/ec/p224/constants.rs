//! Shared constants and helper functions for P-224 operations

/// Size of a P-224 scalar in bytes (28 bytes = 224 bits)
pub const P224_SCALAR_SIZE: usize = 28;

/// Size of a P-224 field element in bytes (28 bytes = 224 bits)
pub const P224_FIELD_ELEMENT_SIZE: usize = 28;

/// Size of an uncompressed P-224 point in bytes: format byte (0x04) + x-coordinate + y-coordinate
pub const P224_POINT_UNCOMPRESSED_SIZE: usize = 1 + 2 * P224_FIELD_ELEMENT_SIZE; // 57 bytes: 0x04 || x || y

/// Size of a compressed P-224 point in bytes: format byte (0x02/0x03) + x-coordinate
pub const P224_POINT_COMPRESSED_SIZE: usize = 1 + P224_FIELD_ELEMENT_SIZE; // 29 bytes: 0x02/0x03 || x

/// Size of the authentication tag for KEM ciphertext
pub const P224_TAG_SIZE: usize = 16; // 16-byte truncated HMAC-SHA256

/// Size of the complete KEM ciphertext: compressed point + authentication tag
pub const P224_CIPHERTEXT_SIZE: usize = P224_POINT_COMPRESSED_SIZE + P224_TAG_SIZE; // 45 bytes total

/// Size of the KDF output for P-224 ECDH-KEM shared secret derivation
pub const P224_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE: usize = 32;