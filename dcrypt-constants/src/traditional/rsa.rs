//! Constants for RSA algorithm

/// RSA with 2048-bit modulus
pub const RSA_MODULUS_2048: usize = 2048;

/// RSA with 3072-bit modulus
pub const RSA_MODULUS_3072: usize = 3072;

/// RSA with 4096-bit modulus
pub const RSA_MODULUS_4096: usize = 4096;

/// Common RSA public exponent (65537)
pub const RSA_PUBLIC_EXPONENT: u32 = 65537;

/// Byte length for RSA-2048 key
pub const RSA_2048_BYTE_LENGTH: usize = RSA_MODULUS_2048 / 8;

/// Byte length for RSA-3072 key
pub const RSA_3072_BYTE_LENGTH: usize = RSA_MODULUS_3072 / 8;

/// Byte length for RSA-4096 key
pub const RSA_4096_BYTE_LENGTH: usize = RSA_MODULUS_4096 / 8;