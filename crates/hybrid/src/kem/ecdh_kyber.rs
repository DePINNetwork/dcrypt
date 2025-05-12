// File: dcrypt-hybrid/src/kem/ecdh_kyber.rs

use api::{Kem as KemTrait, Result};
use kem::ecdh::EcdhP256;
use kem::kyber::Kyber768;
use zeroize::Zeroize;
use rand::{CryptoRng, RngCore};

/// Hybrid KEM combining ECDH P-256 and Kyber-768
pub struct EcdhKyberHybrid;

#[derive(Clone, Zeroize)]
pub struct HybridPublicKey {
    ecdh_pk: <EcdhP256 as KemTrait>::PublicKey,
    kyber_pk: <Kyber768 as KemTrait>::PublicKey,
}

#[derive(Clone, Zeroize)]
pub struct HybridSecretKey {
    ecdh_sk: <EcdhP256 as KemTrait>::SecretKey,
    kyber_sk: <Kyber768 as KemTrait>::SecretKey,
}

#[derive(Clone, Zeroize)]
pub struct HybridSharedSecret {
    data: api::Key,
}

#[derive(Clone)]
pub struct HybridCiphertext {
    ecdh_ct: <EcdhP256 as KemTrait>::Ciphertext,
    kyber_ct: <Kyber768 as KemTrait>::Ciphertext,
}

impl AsRef<[u8]> for HybridPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.ecdh_pk.as_ref()
    }
}

impl AsMut<[u8]> for HybridPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.ecdh_pk.as_mut()
    }
}

impl AsRef<[u8]> for HybridSecretKey {
    fn as_ref(&self) -> &[u8] {
        self.ecdh_sk.as_ref()
    }
}

impl AsMut<[u8]> for HybridSecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.ecdh_sk.as_mut()
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
        self.ecdh_ct.as_ref()
    }
}

impl AsMut<[u8]> for HybridCiphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        self.ecdh_ct.as_mut()
    }
}

impl KemTrait for EcdhKyberHybrid {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SharedSecret = HybridSharedSecret;
    type Ciphertext = HybridCiphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P256 + Kyber-768 Hybrid"
    }

    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> Result<Self::KeyPair> {
        // Generate keypairs for both algorithms
        let (ecdh_pk, ecdh_sk) = EcdhP256::keypair(rng)?;
        let (kyber_pk, kyber_sk) = Kyber768::keypair(rng)?;

        let public_key = HybridPublicKey {
            ecdh_pk,
            kyber_pk,
        };

        let secret_key = HybridSecretKey {
            ecdh_sk,
            kyber_sk,
        };

        Ok((public_key, secret_key))
    }
    
    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }
    
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        // Encapsulate using both algorithms
        let (ecdh_ct, ecdh_ss) = EcdhP256::encapsulate(rng, &public_key.ecdh_pk)?;
        let (kyber_ct, kyber_ss) = Kyber768::encapsulate(rng, &public_key.kyber_pk)?;

        // Combine the shared secrets
        let mut combined = Vec::new();
        combined.extend_from_slice(ecdh_ss.as_ref());
        combined.extend_from_slice(kyber_ss.as_ref());

        let ciphertext = HybridCiphertext {
            ecdh_ct,
            kyber_ct,
        };

        let shared_secret = HybridSharedSecret {
            data: api::Key::new(&combined),
        };

        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret> {
        // Decapsulate using both algorithms
        let ecdh_ss = EcdhP256::decapsulate(&secret_key.ecdh_sk, &ciphertext.ecdh_ct)?;
        let kyber_ss = Kyber768::decapsulate(&secret_key.kyber_sk, &ciphertext.kyber_ct)?;

        // Combine the shared secrets
        let mut combined = Vec::new();
        combined.extend_from_slice(ecdh_ss.as_ref());
        combined.extend_from_slice(kyber_ss.as_ref());

        let shared_secret = HybridSharedSecret {
            data: api::Key::new(&combined),
        };

        Ok(shared_secret)
    }
}