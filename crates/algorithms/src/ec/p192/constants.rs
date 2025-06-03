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

/// Helper function to convert big‐endian bytes to little‐endian limbs
#[inline]
pub fn bytes_to_limbs_le<const L: usize>(be_bytes: &[u8]) -> [u32; L] {
    let mut limbs = [0u32; L];
    for i in 0..L {
        let offset = (L - 1 - i) * 4;
        limbs[i] = u32::from_be_bytes([
            be_bytes[offset],
            be_bytes[offset + 1],
            be_bytes[offset + 2],
            be_bytes[offset + 3],
        ]);
    }
    limbs
}

/// Helper function to convert little‐endian limbs to big‐endian bytes
#[inline]
pub fn limbs_to_bytes_be<const L: usize>(limbs: &[u32; L]) -> Vec<u8> {
    let mut bytes = vec![0u8; L * 4];
    for i in 0..L {
        let offset = (L - 1 - i) * 4;
        bytes[offset..offset + 4].copy_from_slice(&limbs[i].to_be_bytes());
    }
    bytes
}
