// File: dcrypt-hybrid/src/kem/ecdh_ntru.rs

use dcrypt_api::{Kem as KemTrait, Result};
use kem::ecdh::EcdhP384;
use kem::ntru::NtruHps;
use zeroize::Zeroize;
use rand::{CryptoRng, RngCore};

/// Hybrid KEM combining ECDH P-384 and NTRU-HPS
pub struct EcdhNtruHybrid;

#[derive(Clone, Zeroize)]
pub struct HybridPublicKey {
    ecdh_pk: <EcdhP384 as KemTrait>::PublicKey,
    ntru_pk: <NtruHps as KemTrait>::PublicKey,
}

#[derive(Clone, Zeroize)]
pub struct HybridSecretKey {
    ecdh_sk: <EcdhP384 as KemTrait>::SecretKey,
    ntru_sk: <NtruHps as KemTrait>::SecretKey,
}

#[derive(Clone, Zeroize)]
pub struct HybridSharedSecret {
    data: api::Key,
}

#[derive(Clone)]
pub struct HybridCiphertext {
    ecdh_ct: <EcdhP384 as KemTrait>::Ciphertext,
    ntru_ct: <NtruHps as KemTrait>::Ciphertext,
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

impl KemTrait for EcdhNtruHybrid {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SharedSecret = HybridSharedSecret;
    type Ciphertext = HybridCiphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P384 + NTRU-HPS Hybrid"
    }

    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> Result<Self::KeyPair> {
        // Generate keypairs for both algorithms
        let (ecdh_pk, ecdh_sk) = EcdhP384::keypair(rng)?;
        let (ntru_pk, ntru_sk) = NtruHps::keypair(rng)?;

        let public_key = HybridPublicKey {
            ecdh_pk,
            ntru_pk,
        };

        let secret_key = HybridSecretKey {
            ecdh_sk,
            ntru_sk,
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
        let (ecdh_ct, ecdh_ss) = EcdhP384::encapsulate(rng, &public_key.ecdh_pk)?;
        let (ntru_ct, ntru_ss) = NtruHps::encapsulate(rng, &public_key.ntru_pk)?;

        // Combine the shared secrets
        let mut combined = Vec::new();
        combined.extend_from_slice(ecdh_ss.as_ref());
        combined.extend_from_slice(ntru_ss.as_ref());

        let ciphertext = HybridCiphertext {
            ecdh_ct,
            ntru_ct,
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
        let ecdh_ss = EcdhP384::decapsulate(&secret_key.ecdh_sk, &ciphertext.ecdh_ct)?;
        let ntru_ss = NtruHps::decapsulate(&secret_key.ntru_sk, &ciphertext.ntru_ct)?;

        // Combine the shared secrets
        let mut combined = Vec::new();
        combined.extend_from_slice(ecdh_ss.as_ref());
        combined.extend_from_slice(ntru_ss.as_ref());

        let shared_secret = HybridSharedSecret {
            data: api::Key::new(&combined),
        };

        Ok(shared_secret)
    }
}