//! Trait definition for digital signature schemes

use crate::error::Result;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Trait for digital signature schemes
pub trait Signature {
    /// Public key type
    type PublicKey: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Secret key type
    type SecretKey: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Signature type
    type Signature: AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Returns the signature algorithm name
    fn name() -> &'static str;
    
    /// Generate a new keypair
    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R
    ) -> Result<(Self::PublicKey, Self::SecretKey)>;
    
    /// Sign a message using the secret key
    fn sign(
        message: &[u8],
        secret_key: &Self::SecretKey,
    ) -> Result<Self::Signature>;
    
    /// Verify a signature on a message using the public key
    fn verify(
        message: &[u8],
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> Result<()>;
}