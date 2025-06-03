//! Constants for Dilithium digital signature algorithm

/// Dilithium polynomial degree
pub const DILITHIUM_N: usize = 256;

/// Dilithium modulus
pub const DILITHIUM_Q: u32 = 8380417;

/// Common trait for Dilithium parameter sets
pub trait DilithiumParams: Send + Sync + 'static {
    /// Algorithm name
    const NAME: &'static str;

    // Ring parameters
    /// Polynomial degree (always 256 for Dilithium)
    const N: usize = DILITHIUM_N;
    /// Prime modulus q = 2^23 - 2^13 + 1
    const Q: u32 = DILITHIUM_Q;
    /// Dropped bits parameter
    const D_PARAM: u32;

    // Matrix dimensions
    /// Number of polynomials in secret vector s2 and public vector t (rows in A)
    const K_DIM: usize;
    /// Number of polynomials in secret vector s1 and masking vector y (columns in A)
    const L_DIM: usize;

    // Norm bounds
    /// Bound for secret polynomials s1, s2
    const ETA_S1S2: u32;
    /// Range parameter for masking vector y
    const GAMMA1_PARAM: u32;
    /// Number of bits to represent z coefficients
    const GAMMA1_BITS: usize;
    /// Decomposition parameter
    const GAMMA2_PARAM: u32;
    /// Rejection bound
    const BETA_PARAM: u32;
    /// Maximum number of hint bits
    const OMEGA_PARAM: u32;
    /// Number of ±1 coefficients in challenge polynomial
    const TAU_PARAM: usize;

    // Byte sizes
    /// Public key size in bytes
    const PUBLIC_KEY_BYTES: usize;
    /// Secret key size in bytes  
    const SECRET_KEY_BYTES: usize;
    /// Signature size in bytes
    const SIGNATURE_SIZE: usize;
    
    // Seed sizes (all 32 bytes for Dilithium)
    /// Seed size for matrix A generation
    const SEED_RHO_BYTES: usize = 32;
    /// Seed size for secret/error sampling
    const SEED_KEY_BYTES: usize = 32;
    /// Master seed size for key generation
    const SEED_ZETA_BYTES: usize = 32;
    /// Challenge seed size
    const SEED_C_TILDE_BYTES: usize = 32;
    /// Hash output size for tr = H(pk)
    const HASH_TR_BYTES: usize = 32;

    // Additional parameters
    /// Maximum signing attempts
    const MAX_SIGN_ABORTS: u16 = 1000;
    /// Bits for packing w1 coefficients
    const W1_BITS: usize;
}

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

impl DilithiumParams for Dilithium2Params {
    const NAME: &'static str = "Dilithium2";
    const D_PARAM: u32 = 13;
    const K_DIM: usize = 4;
    const L_DIM: usize = 4;
    const ETA_S1S2: u32 = 2;
    const GAMMA1_PARAM: u32 = 1 << 17;  // 2^17
    const GAMMA1_BITS: usize = 18;      // ceil(log2(2*gamma1))
    const GAMMA2_PARAM: u32 = (DILITHIUM_Q - 1) / 88;
    const BETA_PARAM: u32 = 78;
    const OMEGA_PARAM: u32 = 80;
    const TAU_PARAM: usize = 39;
    const PUBLIC_KEY_BYTES: usize = 1312;
    const SECRET_KEY_BYTES: usize = 2528;
    const SIGNATURE_SIZE: usize = 2420;
    const W1_BITS: usize = 6;  // For gamma2 = (q-1)/88
}

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

impl DilithiumParams for Dilithium3Params {
    const NAME: &'static str = "Dilithium3";
    const D_PARAM: u32 = 13;
    const K_DIM: usize = 6;
    const L_DIM: usize = 5;
    const ETA_S1S2: u32 = 4;
    const GAMMA1_PARAM: u32 = 1 << 19;  // 2^19
    const GAMMA1_BITS: usize = 20;      // ceil(log2(2*gamma1))
    const GAMMA2_PARAM: u32 = (DILITHIUM_Q - 1) / 88;
    const BETA_PARAM: u32 = 196;
    const OMEGA_PARAM: u32 = 55;
    const TAU_PARAM: usize = 49;
    const PUBLIC_KEY_BYTES: usize = 1952;
    const SECRET_KEY_BYTES: usize = 4000;
    const SIGNATURE_SIZE: usize = 3293;
    const W1_BITS: usize = 6;  // For gamma2 = (q-1)/88
}

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

impl DilithiumParams for Dilithium5Params {
    const NAME: &'static str = "Dilithium5";
    const D_PARAM: u32 = 13;
    const K_DIM: usize = 8;
    const L_DIM: usize = 7;
    const ETA_S1S2: u32 = 2;
    const GAMMA1_PARAM: u32 = 1 << 19;  // 2^19
    const GAMMA1_BITS: usize = 20;      // ceil(log2(2*gamma1))
    const GAMMA2_PARAM: u32 = (DILITHIUM_Q - 1) / 88;
    const BETA_PARAM: u32 = 261;
    const OMEGA_PARAM: u32 = 75;
    const TAU_PARAM: usize = 60;
    const PUBLIC_KEY_BYTES: usize = 2592;
    const SECRET_KEY_BYTES: usize = 4864;
    const SIGNATURE_SIZE: usize = 4595;
    const W1_BITS: usize = 6;  // For gamma2 = (q-1)/88
}