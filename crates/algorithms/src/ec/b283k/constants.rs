//! Shared constants for sect283k1 operations

/// Size of a sect283k1 scalar in bytes (283 bits -> 36 bytes)
pub const B283K_SCALAR_SIZE: usize = 36;

/// Size of a sect283k1 field element in bytes (283 bits -> 36 bytes)
pub const B283K_FIELD_ELEMENT_SIZE: usize = 36;

/// Size of an uncompressed sect283k1 point in bytes: format byte (0x04) + x-coordinate + y-coordinate
pub const B283K_POINT_UNCOMPRESSED_SIZE: usize = 1 + 2 * B283K_FIELD_ELEMENT_SIZE; // 73 bytes

/// Size of a compressed sect283k1 point in bytes: format byte (0x02/0x03) + x-coordinate
pub const B283K_POINT_COMPRESSED_SIZE: usize = 1 + B283K_FIELD_ELEMENT_SIZE; // 37 bytes

/// Size of the KDF output for sect283k1 ECDH-KEM (matches SHA-384 output)
pub const B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE: usize = 48;
