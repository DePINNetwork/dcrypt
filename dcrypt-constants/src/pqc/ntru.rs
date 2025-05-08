//! Constants for NTRU key encapsulation mechanism

/// NTRU-HPS parameter set
pub struct NtruHpsParams {
    /// Polynomial degree
    pub n: usize,
    
    /// Modulus
    pub q: u16,
    
    /// Padding parameter
    pub p: u16,
    
    /// Weight of private key
    pub d: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Ciphertext size in bytes
    pub ciphertext_size: usize,
    
    /// Shared secret size in bytes
    pub shared_secret_size: usize,
}

/// NTRU-HPS-2048-509 parameters
pub const NTRU_HPS_2048_509: NtruHpsParams = NtruHpsParams {
    n: 509,
    q: 2048,
    p: 3,
    d: 254,
    public_key_size: 699,
    secret_key_size: 935,
    ciphertext_size: 699,
    shared_secret_size: 32,
};

/// NTRU-HPS-2048-677 parameters
pub const NTRU_HPS_2048_677: NtruHpsParams = NtruHpsParams {
    n: 677,
    q: 2048,
    p: 3,
    d: 254,
    public_key_size: 930,
    secret_key_size: 1234,
    ciphertext_size: 930,
    shared_secret_size: 32,
};

/// NTRU-HPS-4096-821 parameters
pub const NTRU_HPS_4096_821: NtruHpsParams = NtruHpsParams {
    n: 821,
    q: 4096,
    p: 3,
    d: 254,
    public_key_size: 1230,
    secret_key_size: 1590,
    ciphertext_size: 1230,
    shared_secret_size: 32,
};

/// NTRU-HRSS parameter set
pub struct NtruHrssParams {
    /// Polynomial degree
    pub n: usize,
    
    /// Modulus
    pub q: u16,
    
    /// Padding parameter
    pub p: u16,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Ciphertext size in bytes
    pub ciphertext_size: usize,
    
    /// Shared secret size in bytes
    pub shared_secret_size: usize,
}

/// NTRU-HRSS-701 parameters
pub const NTRU_HRSS_701: NtruHrssParams = NtruHrssParams {
    n: 701,
    q: 8192,
    p: 3,
    public_key_size: 1138,
    secret_key_size: 1450,
    ciphertext_size: 1138,
    shared_secret_size: 32,
};