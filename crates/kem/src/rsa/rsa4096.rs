//! RSA-KEM with 4096-bit modulus

use super::common::{RsaKemBase, RsaPublicKey, RsaSecretKey, RsaSharedSecret, RsaCiphertext};
use api::{Kem, Result};
use rand::{CryptoRng, RngCore};

/// RSA-KEM with 4096-bit modulus (512 bytes)
pub type RsaKem4096 = RsaKemBase<512>;

// Similar implementation as rsa2048.rs with appropriate parameter changes