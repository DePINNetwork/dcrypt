//! Common RSA-KEM functionality

use api::Key;
use zeroize::Zeroize;
use rand::{CryptoRng, RngCore};

/// Base key size in bytes
const BASE_KEY_SIZE: usize = 32;

/// Common RSA-KEM implementation that can be parametrized with different modulus sizes
pub struct RsaKemBase<const MODULUS_SIZE: usize>;

#[derive(Clone, Zeroize)]
pub struct RsaPublicKey {
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
}

#[derive(Clone, Zeroize)]
pub struct RsaSecretKey {
    pub modulus: Vec<u8>,
    pub private_exponent: Vec<u8>,
}

#[derive(Clone, Zeroize)]
pub struct RsaSharedSecret(pub Key);

#[derive(Clone)]
pub struct RsaCiphertext(pub Vec<u8>);

impl AsRef<[u8]> for RsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.modulus
    }
}

impl AsMut<[u8]> for RsaPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.modulus
    }
}

impl AsRef<[u8]> for RsaSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.modulus
    }
}

impl AsMut<[u8]> for RsaSecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.modulus
    }
}

impl AsRef<[u8]> for RsaSharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for RsaSharedSecret {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl AsRef<[u8]> for RsaCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for RsaCiphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
