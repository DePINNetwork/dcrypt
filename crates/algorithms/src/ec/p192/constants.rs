//! Shared constants and helper functions for P-192 operations

/// Size of a P-192 scalar in bytes (24 bytes = 192 bits)
pub const P192_SCALAR_SIZE: usize = 24;

/// Size of a P-192 field element in bytes (24 bytes = 192 bits)
pub const P192_FIELD_ELEMENT_SIZE: usize = 24;

/// Size of an uncompressed P-192 point in bytes:
/// format byte (0x04) + x-coordinate + y-coordinate
pub const P192_POINT_UNCOMPRESSED_SIZE: usize = 1 + 2 * P192_FIELD_ELEMENT_SIZE; // 49 bytes

/// Size of a compressed P-192 point in bytes:
/// format byte (0x02/0x03) + x-coordinate
pub const P192_POINT_COMPRESSED_SIZE: usize = 1 + P192_FIELD_ELEMENT_SIZE; // 25 bytes

/// Size of the KDF output for P-192 ECDH‐KEM shared secret derivation
pub const P192_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE: usize = 32;
