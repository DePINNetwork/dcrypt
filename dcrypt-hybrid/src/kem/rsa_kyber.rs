// File: dcrypt-hybrid/src/kem/rsa_kyber.rs
//! RSA + Kyber hybrid KEM
//!
//! This module implements a hybrid KEM that combines RSA-KEM and Kyber.

use dcrypt_core::{Kem as KemTrait, Result};
use dcrypt_kem::rsa::RsaKem2048;
use dcrypt_kem::kyber::Kyber768;
use zeroize::Zeroize;
use rand::{CryptoRng, RngCore};

/// Hybrid KEM combining RSA-2048 and Kyber-768
pub struct RsaKyberHybrid;

#[derive(Clone, Zeroize)]
pub struct HybridPublicKey {
    rsa_pk: <RsaKem2048 as KemTrait>::PublicKey,
    kyber_pk: <Kyber768 as KemTrait>::PublicKey,
}

#[derive(Clone, Zeroize)]
pub struct HybridSecretKey {
    rsa_sk: <RsaKem2048 as KemTrait>::SecretKey,
    kyber_sk: <Kyber768 as KemTrait>::SecretKey,
}

#[derive(Clone, Zeroize)]
pub struct HybridSharedSecret {
    data: dcrypt_core::Key,
}

#[derive(Clone)]
pub struct HybridCiphertext {
    rsa_ct: <RsaKem2048 as KemTrait>::Ciphertext,
    kyber_ct: <Kyber768 as KemTrait>::Ciphertext,
}

impl AsRef<[u8]> for HybridPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.rsa_pk.as_ref()
    }
}

impl AsMut<[u8]> for HybridPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.rsa_pk.as_mut()
    }
}

impl AsRef<[u8]> for HybridSecretKey {
    fn as_ref(&self) -> &[u8] {
        self.rsa_sk.as_ref()
    }
}

impl AsMut<[u8]> for HybridSecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.rsa_sk.as_mut()
    }
}

impl AsRef<[u8]> for HybridSharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl AsMut<[u8]> for HybridSharedSecret {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl AsRef<[u8]> for HybridCiphertext {
    fn as_ref(&self) -> &[u8] {
        self.rsa_ct.as_ref()
    }
}

impl AsMut<[u8]> for HybridCiphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        self.rsa_ct.as_mut()
    }
}

impl KemTrait for RsaKyberHybrid {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SharedSecret = HybridSharedSecret;
    type Ciphertext = HybridCiphertext;

    fn name() -> &'static str {
        "RSA-2048 + Kyber-768 Hybrid"
    }

    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey)> {
        // Generate keypairs for both algorithms
        let (rsa_pk, rsa_sk) = RsaKem2048::keypair(rng)?;
        let (kyber_pk, kyber_sk) = Kyber768::keypair(rng)?;

        let public_key = HybridPublicKey {
            rsa_pk,
            kyber_pk,
        };

        let secret_key = HybridSecretKey {
            rsa_sk,
            kyber_sk,
        };

        Ok((public_key, secret_key))
    }

    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        // Encapsulate using both algorithms
        let (rsa_ct, rsa_ss) = RsaKem2048::encapsulate(rng, &public_key.rsa_pk)?;
        let (kyber_ct, kyber_ss) = Kyber768::encapsulate(rng, &public_key.kyber_pk)?;

        // Combine the shared secrets
        let mut combined = Vec::new();
        combined.extend_from_slice(rsa_ss.as_ref());
        combined.extend_from_slice(kyber_ss.as_ref());

        let ciphertext = HybridCiphertext {
            rsa_ct,
            kyber_ct,
        };

        let shared_secret = HybridSharedSecret {
            data: dcrypt_core::Key::new(&combined),
        };

        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret> {
        // Decapsulate using both algorithms
        let rsa_ss = RsaKem2048::decapsulate(&secret_key.rsa_sk, &ciphertext.rsa_ct)?;
        let kyber_ss = Kyber768::decapsulate(&secret_key.kyber_sk, &ciphertext.kyber_ct)?;

        // Combine the shared secrets
        let mut combined = Vec::new();
        combined.extend_from_slice(rsa_ss.as_ref());
        combined.extend_from_slice(kyber_ss.as_ref());

        let shared_secret = HybridSharedSecret {
            data: dcrypt_core::Key::new(&combined),
        };

        Ok(shared_secret)
    }
}