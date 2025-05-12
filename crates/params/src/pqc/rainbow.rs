//! Constants for Rainbow signature algorithm

/// Structure containing Rainbow-I parameters
pub struct RainbowIParams {
    /// Number of variables
    pub v: usize,
    
    /// Number of oil variables for each layer
    pub o: [usize; 1],
    
    /// Number of equations for central map
    pub l: [usize; 2],
    
    /// Field size
    pub q: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// Rainbow-I parameters (NIST security level 1)
pub const RAINBOW_I: RainbowIParams = RainbowIParams {
    v: 100,
    o: [36],
    l: [32, 32],
    q: 16,
    public_key_size: 161600,
    secret_key_size: 103648,
    signature_size: 64,
};

/// Structure containing Rainbow-III parameters
pub struct RainbowIIIParams {
    /// Number of variables
    pub v: usize,
    
    /// Number of oil variables for each layer
    pub o: [usize; 1],
    
    /// Number of equations for central map
    pub l: [usize; 2],
    
    /// Field size
    pub q: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// Rainbow-III parameters (NIST security level 3)
pub const RAINBOW_III: RainbowIIIParams = RainbowIIIParams {
    v: 148,
    o: [56],
    l: [48, 44],
    q: 256,
    public_key_size: 861400,
    secret_key_size: 611300,
    signature_size: 96,
};

/// Structure containing Rainbow-V parameters
pub struct RainbowVParams {
    /// Number of variables
    pub v: usize,
    
    /// Number of oil variables for each layer
    pub o: [usize; 1],
    
    /// Number of equations for central map
    pub l: [usize; 2],
    
    /// Field size
    pub q: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// Rainbow-V parameters (NIST security level 5)
pub const RAINBOW_V: RainbowVParams = RainbowVParams {
    v: 196,
    o: [84],
    l: [64, 48],
    q: 256,
    public_key_size: 1885400,
    secret_key_size: 1375700,
    signature_size: 128,
};