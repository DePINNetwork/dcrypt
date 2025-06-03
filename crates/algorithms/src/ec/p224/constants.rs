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

/// Helper function to convert big-endian bytes to little-endian limbs
/// For P-224, this reads big-endian bytes from parameter tables and converts
/// them to little-endian limb representation for internal arithmetic
#[inline]
pub fn bytes_to_limbs_le<const L: usize>(be_bytes: &[u8]) -> [u32; L] {
    let mut limbs = [0u32; L];
    for i in 0..L {
        let offset = i * 4;
        // Read from big-endian bytes, store in reverse order for little-endian limbs
        limbs[L - 1 - i] = u32::from_be_bytes([
            be_bytes[offset],
            be_bytes[offset + 1],
            be_bytes[offset + 2],
            be_bytes[offset + 3],
        ]);
    }
    limbs
}

/// Helper function to convert little-endian limbs to big-endian bytes
/// For P-224, this converts internal little-endian limb representation
/// back to big-endian bytes for external use
#[inline]
pub fn limbs_to_bytes_be<const L: usize>(limbs: &[u32; L]) -> Vec<u8> {
    let mut bytes = vec![0u8; L * 4];
    for i in 0..L {
        let offset = i * 4;
        // Read from little-endian limbs in reverse order, write as big-endian bytes
        bytes[offset..offset + 4].copy_from_slice(&limbs[L - 1 - i].to_be_bytes());
    }
    bytes
}