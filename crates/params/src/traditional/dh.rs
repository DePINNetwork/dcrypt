//! Constants for Diffie-Hellman key exchange

/// DH with 2048-bit modulus
pub const DH_MODULUS_2048: usize = 2048;

/// DH with 3072-bit modulus
pub const DH_MODULUS_3072: usize = 3072;

/// DH with 4096-bit modulus
pub const DH_MODULUS_4096: usize = 4096;

/// Byte length for DH-2048 key
pub const DH_2048_BYTE_LENGTH: usize = DH_MODULUS_2048 / 8;

/// Byte length for DH-3072 key
pub const DH_3072_BYTE_LENGTH: usize = DH_MODULUS_3072 / 8;

/// Byte length for DH-4096 key
pub const DH_4096_BYTE_LENGTH: usize = DH_MODULUS_4096 / 8;

// RFC 3526 MODP Group 14 (2048 bits) generator
pub const DH_2048_GENERATOR: u32 = 2;

// First few bytes of RFC 3526 MODP Group 14 (2048 bits) prime
pub const DH_2048_PRIME_HEAD: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
