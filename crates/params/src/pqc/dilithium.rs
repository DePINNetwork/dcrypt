//! Constants for Dilithium digital signature algorithm

/// Dilithium polynomial degree
pub const DILITHIUM_N: usize = 256;

/// Dilithium modulus
pub const DILITHIUM_Q: u32 = 8380417;

/// Structure containing Dilithium2 parameters
pub struct Dilithium2Params {
    /// Polynomial degree
    pub n: usize,
    
    /// Modulus
    pub q: u32,
    
    /// Dropped bits in t
    pub d: u32,
    
    /// Dimension parameter (rows in matrix)
    pub k: usize,
    
    /// Dimension parameter (columns in matrix)
    pub l: usize,
    
    /// Infinity norm bound parameter
    pub eta: u32,
    
    /// Challenge sparsity
    pub tau: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// Dilithium2 parameters (NIST security level 2)
pub const DILITHIUM2: Dilithium2Params = Dilithium2Params {
    n: DILITHIUM_N,
    q: DILITHIUM_Q,
    d: 13,
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    public_key_size: 1312,
    secret_key_size: 2528,
    signature_size: 2420,
};

/// Structure containing Dilithium3 parameters
pub struct Dilithium3Params {
    /// Polynomial degree
    pub n: usize,
    
    /// Modulus
    pub q: u32,
    
    /// Dropped bits in t
    pub d: u32,
    
    /// Dimension parameter (rows in matrix)
    pub k: usize,
    
    /// Dimension parameter (columns in matrix)
    pub l: usize,
    
    /// Infinity norm bound parameter
    pub eta: u32,
    
    /// Challenge sparsity
    pub tau: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// Dilithium3 parameters (NIST security level 3)
pub const DILITHIUM3: Dilithium3Params = Dilithium3Params {
    n: DILITHIUM_N,
    q: DILITHIUM_Q,
    d: 13,
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    public_key_size: 1952,
    secret_key_size: 4000,
    signature_size: 3293,
};

/// Structure containing Dilithium5 parameters
pub struct Dilithium5Params {
    /// Polynomial degree
    pub n: usize,
    
    /// Modulus
    pub q: u32,
    
    /// Dropped bits in t
    pub d: u32,
    
    /// Dimension parameter (rows in matrix)
    pub k: usize,
    
    /// Dimension parameter (columns in matrix)
    pub l: usize,
    
    /// Infinity norm bound parameter
    pub eta: u32,
    
    /// Challenge sparsity
    pub tau: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// Dilithium5 parameters (NIST security level 5)
pub const DILITHIUM5: Dilithium5Params = Dilithium5Params {
    n: DILITHIUM_N,
    q: DILITHIUM_Q,
    d: 13,
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    public_key_size: 2592,
    secret_key_size: 4864,
    signature_size: 4595,
};