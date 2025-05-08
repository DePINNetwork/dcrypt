//! Common Kyber KEM functionality

use dcrypt_core::{Key, Kem, Serialize, DcryptError, Result};
use zeroize::Zeroize;
use rand::{CryptoRng, RngCore};

/// Base key size in bytes
const BASE_KEY_SIZE: usize = 32;

/// Common Kyber implementation that can be parametrized with different parameters
pub struct KyberBase<const K: usize>;

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
