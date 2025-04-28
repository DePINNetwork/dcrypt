//! Trait definition for Key Encapsulation Mechanisms (KEM)

use crate::error::Result;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Trait for Key Encapsulation Mechanism (KEM)
pub trait Kem {
    /// Public key type
    type PublicKey: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Secret key type
    type SecretKey: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Shared secret type
    type SharedSecret: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Ciphertext type
    type Ciphertext: AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Returns the KEM algorithm name
    fn name() -> &'static str;
    
    /// Generate a new keypair
    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R
    ) -> Result<(Self::PublicKey, Self::SecretKey)>;
    
    /// Encapsulate a shared secret using the recipient's public key
    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &Self::PublicKey
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)>;
    
    /// Decapsulate a shared secret using the private key
    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext
    ) -> Result<Self::SharedSecret>;
}