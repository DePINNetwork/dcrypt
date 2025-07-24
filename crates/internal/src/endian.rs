//! Endianness utility functions

/// Convert a u32 from little-endian byte order to native byte order
pub fn u32_from_le_bytes(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Convert a u32 from big-endian byte order to native byte order
pub fn u32_from_be_bytes(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Convert a u32 from native byte order to little-endian bytes
pub fn u32_to_le_bytes(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Convert a u32 from native byte order to big-endian bytes
pub fn u32_to_be_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Convert a u64 from little-endian byte order to native byte order
pub fn u64_from_le_bytes(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Convert a u64 from big-endian byte order to native byte order
pub fn u64_from_be_bytes(bytes: &[u8]) -> u64 {
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Convert a u64 from native byte order to little-endian bytes
pub fn u64_to_le_bytes(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// Convert a u64 from native byte order to big-endian bytes
pub fn u64_to_be_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}
