//! Constants for Classic McEliece key encapsulation mechanism

/// Structure containing McEliece-348864 parameters
pub struct McEliece348864Params {
    /// Code length
    pub n: usize,

    /// Code dimension
    pub k: usize,

    /// Error correction capability
    pub t: usize,

    /// Public key size in bytes
    pub public_key_size: usize,

    /// Secret key size in bytes
    pub secret_key_size: usize,

    /// Ciphertext size in bytes
    pub ciphertext_size: usize,

    /// Shared secret size in bytes
    pub shared_secret_size: usize,
}

/// McEliece-348864 parameters (NIST security level 1)
pub const MCELIECE_348864: McEliece348864Params = McEliece348864Params {
    n: 3488,
    k: 2720,
    t: 64,
    public_key_size: 261120,
    secret_key_size: 6492,
    ciphertext_size: 128,
    shared_secret_size: 32,
};

/// Structure containing McEliece-460896 parameters
pub struct McEliece460896Params {
    /// Code length
    pub n: usize,

    /// Code dimension
    pub k: usize,

    /// Error correction capability
    pub t: usize,

    /// Public key size in bytes
    pub public_key_size: usize,

    /// Secret key size in bytes
    pub secret_key_size: usize,

    /// Ciphertext size in bytes
    pub ciphertext_size: usize,

    /// Shared secret size in bytes
    pub shared_secret_size: usize,
}

/// McEliece-460896 parameters (NIST security level 3)
pub const MCELIECE_460896: McEliece460896Params = McEliece460896Params {
    n: 4608,
    k: 3360,
    t: 96,
    public_key_size: 524160,
    secret_key_size: 13608,
    ciphertext_size: 188,
    shared_secret_size: 32,
};

/// Structure containing McEliece-6960119 parameters
pub struct McEliece6960119Params {
    /// Code length
    pub n: usize,

    /// Code dimension
    pub k: usize,

    /// Error correction capability
    pub t: usize,

    /// Public key size in bytes
    pub public_key_size: usize,

    /// Secret key size in bytes
    pub secret_key_size: usize,

    /// Ciphertext size in bytes
    pub ciphertext_size: usize,

    /// Shared secret size in bytes
    pub shared_secret_size: usize,
}

/// McEliece-6960119 parameters (NIST security level 5)
pub const MCELIECE_6960119: McEliece6960119Params = McEliece6960119Params {
    n: 6960,
    k: 5413,
    t: 119,
    public_key_size: 1047319,
    secret_key_size: 13932,
    ciphertext_size: 240,
    shared_secret_size: 32,
};
