//! Constants for SABER key encapsulation mechanism

/// SABER polynomial degree
pub const SABER_N: usize = 256;

/// SABER modulus
pub const SABER_Q: u16 = 8192;

/// SABER encoding modulus
pub const SABER_P: u16 = 1024;

/// Structure containing LightSABER parameters
pub struct LightSaberParams {
    /// Polynomial degree
    pub n: usize,

    /// Modulus
    pub q: u16,

    /// Encoding modulus
    pub p: u16,

    /// Number of polynomials (dimension)
    pub l: usize,

    /// Modulus for rounding
    pub t: u16,

    /// Bits for compression of A
    pub eq: usize,

    /// Bits for compression of B
    pub ep: usize,

    /// Bits for compression of s
    pub et: usize,

    /// Public key size in bytes
    pub public_key_size: usize,

    /// Secret key size in bytes
    pub secret_key_size: usize,

    /// Ciphertext size in bytes
    pub ciphertext_size: usize,

    /// Shared secret size in bytes
    pub shared_secret_size: usize,
}

/// LightSABER parameters (128-bit security)
pub const LIGHTSABER: LightSaberParams = LightSaberParams {
    n: SABER_N,
    q: SABER_Q,
    p: SABER_P,
    l: 2,
    t: 1024, // 2^10
    eq: 13,
    ep: 10,
    et: 3,
    public_key_size: 672,
    secret_key_size: 1568,
    ciphertext_size: 736,
    shared_secret_size: 32,
};

/// Structure containing SABER parameters
pub struct SaberParams {
    /// Polynomial degree
    pub n: usize,

    /// Modulus
    pub q: u16,

    /// Encoding modulus
    pub p: u16,

    /// Number of polynomials (dimension)
    pub l: usize,

    /// Modulus for rounding
    pub t: u16,

    /// Bits for compression of A
    pub eq: usize,

    /// Bits for compression of B
    pub ep: usize,

    /// Bits for compression of s
    pub et: usize,

    /// Public key size in bytes
    pub public_key_size: usize,

    /// Secret key size in bytes
    pub secret_key_size: usize,

    /// Ciphertext size in bytes
    pub ciphertext_size: usize,

    /// Shared secret size in bytes
    pub shared_secret_size: usize,
}

/// SABER parameters (192-bit security)
pub const SABER: SaberParams = SaberParams {
    n: SABER_N,
    q: SABER_Q,
    p: SABER_P,
    l: 3,
    t: 1024, // 2^10
    eq: 13,
    ep: 10,
    et: 4,
    public_key_size: 992,
    secret_key_size: 2304,
    ciphertext_size: 1088,
    shared_secret_size: 32,
};

/// Structure containing FireSABER parameters
pub struct FireSaberParams {
    /// Polynomial degree
    pub n: usize,

    /// Modulus
    pub q: u16,

    /// Encoding modulus
    pub p: u16,

    /// Number of polynomials (dimension)
    pub l: usize,

    /// Modulus for rounding
    pub t: u16,

    /// Bits for compression of A
    pub eq: usize,

    /// Bits for compression of B
    pub ep: usize,

    /// Bits for compression of s
    pub et: usize,

    /// Public key size in bytes
    pub public_key_size: usize,

    /// Secret key size in bytes
    pub secret_key_size: usize,

    /// Ciphertext size in bytes
    pub ciphertext_size: usize,

    /// Shared secret size in bytes
    pub shared_secret_size: usize,
}

/// FireSABER parameters (256-bit security)
pub const FIRESABER: FireSaberParams = FireSaberParams {
    n: SABER_N,
    q: SABER_Q,
    p: SABER_P,
    l: 4,
    t: 1024, // 2^10
    eq: 13,
    ep: 10,
    et: 6,
    public_key_size: 1312,
    secret_key_size: 3040,
    ciphertext_size: 1472,
    shared_secret_size: 32,
};
