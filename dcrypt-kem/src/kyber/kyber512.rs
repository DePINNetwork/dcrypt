//! Kyber-512 KEM

use super::common::{KyberBase, KyberPublicKey, KyberSecretKey, KyberSharedSecret, KyberCiphertext};
use dcrypt_core::{Kem, Result};
use rand::{CryptoRng, RngCore};

/// Kyber-512 KEM with parameter k=2
pub type Kyber512 = KyberBase<2>;

// Similar implementation as kyber768.rs with appropriate parameter changes