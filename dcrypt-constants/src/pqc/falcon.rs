//! Constants for Falcon signature algorithm

/// Falcon degree parameter size for Falcon-512
pub const FALCON_512_N: usize = 512;

/// Falcon degree parameter size for Falcon-1024
pub const FALCON_1024_N: usize = 1024;

/// Structure containing Falcon-512 parameters
pub struct Falcon512Params {
    /// Polynomial degree
    pub n: usize,
    
    /// Modulus
    pub q: u16,
    
    /// Standard deviation for signatures
    pub sigma: f64,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// Falcon-512 parameters (NIST security level 1)
pub const FALCON512: Falcon512Params = Falcon512Params {
    n: FALCON_512_N,
    q: 12289,
    sigma: 165.0,
    public_key_size: 897,
    secret_key_size: 1281,
    signature_size: 666,
};

/// Structure containing Falcon-1024 parameters
pub struct Falcon1024Params {
    /// Polynomial degree
    pub n: usize,
    
    /// Modulus
    pub q: u16,
    
    /// Standard deviation for signatures
    pub sigma: f64,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// Falcon-1024 parameters (NIST security level 5)
pub const FALCON1024: Falcon1024Params = Falcon1024Params {
    n: FALCON_1024_N,
    q: 12289,
    sigma: 168.0,
    public_key_size: 1793,
    secret_key_size: 2305,
    signature_size: 1280,
};