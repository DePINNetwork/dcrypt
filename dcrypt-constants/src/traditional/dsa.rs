//! Constants for Digital Signature Algorithm (DSA)

/// DSA with 2048-bit modulus and 256-bit subgroup
pub const DSA_2048_256: (usize, usize) = (2048, 256);

/// DSA with 3072-bit modulus and 256-bit subgroup
pub const DSA_3072_256: (usize, usize) = (3072, 256);

/// Size of DSA signatures in bytes (r and s concatenated)
pub const DSA_SIGNATURE_SIZE: usize = 64;

/// Byte length for DSA 2048-bit modulus
pub const DSA_2048_P_BYTE_LENGTH: usize = 2048 / 8;

/// Byte length for DSA 3072-bit modulus
pub const DSA_3072_P_BYTE_LENGTH: usize = 3072 / 8;

/// Byte length for DSA 256-bit subgroup order
pub const DSA_256_Q_BYTE_LENGTH: usize = 256 / 8;