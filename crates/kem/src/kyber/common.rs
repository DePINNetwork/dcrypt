//! Common Kyber KEM functionality

use api::{Key, Kem, Serialize};
use zeroize::Zeroize;
use rand::{CryptoRng, RngCore};
use crate::error::{Error, Result, validate};

/// Base key size in bytes
pub const BASE_KEY_SIZE: usize = 32;

/// Common Kyber implementation that can be parametrized with different parameters
pub struct KyberBase<const K: usize>;

// Size constants for different Kyber variants
pub const KYBER512_SIZES: KyberSizes = KyberSizes {
    public_key: 800,
    secret_key: 1632,
    ciphertext: 768,
    shared_secret: 32,
};

pub const KYBER768_SIZES: KyberSizes = KyberSizes {
    public_key: 1184,
    secret_key: 2400,
    ciphertext: 1088,
    shared_secret: 32,
};

pub const KYBER1024_SIZES: KyberSizes = KyberSizes {
    public_key: 1568,
    secret_key: 3168,
    ciphertext: 1568,
    shared_secret: 32,
};

#[derive(Debug, Clone, Copy)]
pub struct KyberSizes {
    pub public_key: usize,
    pub secret_key: usize,
    pub ciphertext: usize,
    pub shared_secret: usize,
}

#[derive(Clone, Zeroize)]
pub struct KyberPublicKey(pub Vec<u8>);

#[derive(Clone, Zeroize)]
pub struct KyberSecretKey(pub Vec<u8>);

#[derive(Clone, Zeroize)]
pub struct KyberSharedSecret(pub Key);

#[derive(Clone)]
pub struct KyberCiphertext(pub Vec<u8>);

impl AsRef<[u8]> for KyberPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for KyberPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for KyberSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for KyberSecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for KyberSharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for KyberSharedSecret {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl AsRef<[u8]> for KyberCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for KyberCiphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// Common validation functions for Kyber
pub fn validate_kyber_parameters<const K: usize>(algorithm: &'static str) -> Result<()> {
    match K {
        2 | 3 | 4 => Ok(()),
        _ => Err(Error::InvalidKey {
            key_type: algorithm,
            reason: "invalid Kyber parameter k, must be 2, 3, or 4",
        }),
    }
}

pub fn get_sizes_for_k<const K: usize>() -> Result<KyberSizes> {
    match K {
        2 => Ok(KYBER512_SIZES),
        3 => Ok(KYBER768_SIZES),
        4 => Ok(KYBER1024_SIZES),
        _ => Err(Error::InvalidKey {
            key_type: "Kyber",
            reason: "invalid parameter k",
        }),
    }
}