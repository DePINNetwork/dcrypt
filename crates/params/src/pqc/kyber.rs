//! Constants for Kyber key encapsulation mechanism

/// Kyber polynomial degree
pub const KYBER_N: usize = 256;

/// Kyber modulus
pub const KYBER_Q: u16 = 3329;

/// Structure containing Kyber-512 parameters
pub struct Kyber512Params {
    /// Polynomial degree
    pub n: usize,

    /// Modulus
    pub q: u16,

    /// Number of polynomials (dimension)
    pub k: usize,

    /// Error distribution parameter
    pub eta1: u8,

    /// Error distribution parameter
    pub eta2: u8,

    /// Number of bits dropped for compression of public key
    pub du: usize,

    /// Number of bits dropped for compression of ciphertext
    pub dv: usize,

    /// Size of public key in bytes
    pub public_key_size: usize,

    /// Size of secret key in bytes
    pub secret_key_size: usize,

    /// Size of ciphertext in bytes
    pub ciphertext_size: usize,

    /// Size of shared secret in bytes
    pub shared_secret_size: usize,
}

/// Kyber-512 parameters
pub const KYBER512: Kyber512Params = Kyber512Params {
    n: KYBER_N,
    q: KYBER_Q,
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
    public_key_size: 800,
    secret_key_size: 1632,
    ciphertext_size: 768,
    shared_secret_size: 32,
};

/// Structure containing Kyber-768 parameters
pub struct Kyber768Params {
    /// Polynomial degree
    pub n: usize,

    /// Modulus
    pub q: u16,

    /// Number of polynomials (dimension)
    pub k: usize,

    /// Error distribution parameter
    pub eta1: u8,

    /// Error distribution parameter
    pub eta2: u8,

    /// Number of bits dropped for compression of public key
    pub du: usize,

    /// Number of bits dropped for compression of ciphertext
    pub dv: usize,

    /// Size of public key in bytes
    pub public_key_size: usize,

    /// Size of secret key in bytes
    pub secret_key_size: usize,

    /// Size of ciphertext in bytes
    pub ciphertext_size: usize,

    /// Size of shared secret in bytes
    pub shared_secret_size: usize,
}

/// Kyber-768 parameters
pub const KYBER768: Kyber768Params = Kyber768Params {
    n: KYBER_N,
    q: KYBER_Q,
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
    public_key_size: 1184,
    secret_key_size: 2400,
    ciphertext_size: 1088,
    shared_secret_size: 32,
};

/// Structure containing Kyber-1024 parameters
pub struct Kyber1024Params {
    /// Polynomial degree
    pub n: usize,

    /// Modulus
    pub q: u16,

    /// Number of polynomials (dimension)
    pub k: usize,

    /// Error distribution parameter
    pub eta1: u8,

    /// Error distribution parameter
    pub eta2: u8,

    /// Number of bits dropped for compression of public key
    pub du: usize,

    /// Number of bits dropped for compression of ciphertext
    pub dv: usize,

    /// Size of public key in bytes
    pub public_key_size: usize,

    /// Size of secret key in bytes
    pub secret_key_size: usize,

    /// Size of ciphertext in bytes
    pub ciphertext_size: usize,

    /// Size of shared secret in bytes
    pub shared_secret_size: usize,
}

/// Kyber-1024 parameters
pub const KYBER1024: Kyber1024Params = Kyber1024Params {
    n: KYBER_N,
    q: KYBER_Q,
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
    public_key_size: 1568,
    secret_key_size: 3168,
    ciphertext_size: 1568,
    shared_secret_size: 32,
};
