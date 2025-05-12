//! Constants for SPHINCS+ hash-based signatures

/// SPHINCS+ parameter set using SHA-256
pub struct SphincsSha256Params {
    /// Security level in bits
    pub security: usize,
    
    /// Height of the hypertree
    pub h: usize,
    
    /// Number of layers in the hypertree
    pub d: usize,
    
    /// Winternitz parameter
    pub w: usize,
    
    /// Number of FORS trees
    pub k: usize,
    
    /// Height of FORS trees
    pub t: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// SPHINCS+-SHA256-128s parameters
pub const SPHINCS_SHA256_128S: SphincsSha256Params = SphincsSha256Params {
    security: 128,
    h: 16,
    d: 2,
    w: 16,
    k: 10,
    t: 16,
    public_key_size: 32,
    secret_key_size: 64,
    signature_size: 7856,
};

/// SPHINCS+-SHA256-128f parameters
pub const SPHINCS_SHA256_128F: SphincsSha256Params = SphincsSha256Params {
    security: 128,
    h: 60,
    d: 20,
    w: 16,
    k: 14,
    t: 12,
    public_key_size: 32,
    secret_key_size: 64,
    signature_size: 16976,
};

/// SPHINCS+-SHA256-192s parameters
pub const SPHINCS_SHA256_192S: SphincsSha256Params = SphincsSha256Params {
    security: 192,
    h: 24,
    d: 3,
    w: 16,
    k: 14,
    t: 17,
    public_key_size: 48,
    secret_key_size: 96,
    signature_size: 16224,
};

/// SPHINCS+-SHA256-192f parameters
pub const SPHINCS_SHA256_192F: SphincsSha256Params = SphincsSha256Params {
    security: 192,
    h: 66,
    d: 22,
    w: 16,
    k: 17,
    t: 13,
    public_key_size: 48,
    secret_key_size: 96,
    signature_size: 35664,
};

/// SPHINCS+ parameter set using SHAKE-256
pub struct SphincsShakeParams {
    /// Security level in bits
    pub security: usize,
    
    /// Height of the hypertree
    pub h: usize,
    
    /// Number of layers in the hypertree
    pub d: usize,
    
    /// Winternitz parameter
    pub w: usize,
    
    /// Number of FORS trees
    pub k: usize,
    
    /// Height of FORS trees
    pub t: usize,
    
    /// Public key size in bytes
    pub public_key_size: usize,
    
    /// Secret key size in bytes
    pub secret_key_size: usize,
    
    /// Signature size in bytes
    pub signature_size: usize,
}

/// SPHINCS+-SHAKE-128s parameters
pub const SPHINCS_SHAKE_128S: SphincsShakeParams = SphincsShakeParams {
    security: 128,
    h: 16,
    d: 2,
    w: 16,
    k: 10,
    t: 16,
    public_key_size: 32,
    secret_key_size: 64,
    signature_size: 7856,
};