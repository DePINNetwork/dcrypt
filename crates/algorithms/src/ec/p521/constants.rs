//! Shared constants and helper functions for P-521 operations

/// Size of a P-521 scalar in bytes (66 bytes)
pub const P521_SCALAR_SIZE: usize = 66;

/// Size of a P-521 field element in bytes (66 bytes)
pub const P521_FIELD_ELEMENT_SIZE: usize = 66;

/// Size of an uncompressed P-521 point in bytes: format byte (0x04) + x-coordinate + y-coordinate
pub const P521_POINT_UNCOMPRESSED_SIZE: usize = 1 + 2 * P521_FIELD_ELEMENT_SIZE; // 1 + 132 = 133 bytes

/// Size of a compressed P-521 point in bytes: format byte (0x02/0x03) + x-coordinate
pub const P521_POINT_COMPRESSED_SIZE: usize = 1 + P521_FIELD_ELEMENT_SIZE; // 1 + 66 = 67 bytes

/// Size of the KDF output for P-521 ECDH-KEM shared secret derivation (e.g., for HKDF-SHA512)
pub const P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE: usize = 64;

/// Number of 32-bit limbs for P-521 field elements and scalars
pub(crate) const P521_LIMBS: usize = 17;

/// Converts 66 big-endian bytes to 17 little-endian u32 limbs for P-521.
/// The most significant limb (limbs[16]) will only use its lowest 9 bits (521 mod 32 = 9).
pub(crate) fn p521_bytes_to_limbs(bytes_be: &[u8; P521_FIELD_ELEMENT_SIZE]) -> [u32; P521_LIMBS] {
    let mut limbs = [0u32; P521_LIMBS];
    #[allow(clippy::needless_range_loop)]
    for i in 0..16 { // First 16 limbs are full
        let offset = P521_FIELD_ELEMENT_SIZE - 4 - (i * 4);
        limbs[i] = u32::from_be_bytes([
            bytes_be[offset],
            bytes_be[offset + 1],
            bytes_be[offset + 2],
            bytes_be[offset + 3],
        ]);
    }
    // Last limb (most significant) from the first 2 bytes (16 bits), but only 9 bits are used.
    // bytes_be[0] (MSB of input), bytes_be[1]
    limbs[16] = ((bytes_be[0] as u32) << 8) | (bytes_be[1] as u32);
    limbs[16] &= (1 << 9) - 1; // Mask to 9 bits (2^9 -1) is 0x1FF

    limbs
}

/// Converts 17 little-endian u32 limbs to 66 big-endian bytes for P-521.
pub(crate) fn p521_limbs_to_bytes(limbs: &[u32; P521_LIMBS]) -> [u8; P521_FIELD_ELEMENT_SIZE] {
    let mut bytes_be = [0u8; P521_FIELD_ELEMENT_SIZE];
    #[allow(clippy::needless_range_loop)]
    for i in 0..16 { // First 16 limbs
        let limb_bytes = limbs[i].to_be_bytes();
        let offset = P521_FIELD_ELEMENT_SIZE - 4 - (i * 4);
        bytes_be[offset..offset + 4].copy_from_slice(&limb_bytes);
    }
    // Last limb (most significant)
    let ms_limb_val = limbs[16] & 0x1FF; // Ensure only 9 bits are used
    bytes_be[0] = (ms_limb_val >> 8) as u8; // Top bit of the 9 bits
    bytes_be[1] = (ms_limb_val & 0xFF) as u8; // Lower 8 bits of the 9 bits

    // Zero out the unused top 7 bits of the first byte if necessary (though ms_limb_val >> 8 already handles it)
    bytes_be[0] &= 0x01; // Since it's 2^521-1, the MSB of the first byte can only be 0 or 1.

    bytes_be
}