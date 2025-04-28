//! FIPS test vectors

/// Known-answer test vector for AES-256
#[derive(Debug)]
pub struct AesKat {
    /// AES key
    pub key: &'static [u8],
    /// Initialization vector
    pub iv: &'static [u8],
    /// Plaintext
    pub plaintext: &'static [u8],
    /// Expected ciphertext
    pub ciphertext: &'static [u8],
}

/// Known-answer test vector for SHA-256
#[derive(Debug)]
pub struct Sha256Kat {
    /// Input message
    pub message: &'static [u8],
    /// Expected digest
    pub digest: &'static [u8],
}

/// Known-answer test vectors for AES-256
pub const AES_VECTORS: &[AesKat] = &[];  // Would contain actual test vectors

/// Known-answer test vectors for SHA-256
pub const SHA256_VECTORS: &[Sha256Kat] = &[];  // Would contain actual test vectors
