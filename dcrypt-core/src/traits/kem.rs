//! Trait definition for Key Encapsulation Mechanisms (KEM) with enhanced type safety
//!
//! This module provides a type-safe interface for key encapsulation mechanisms,
//! which are used for secure key exchange in public-key cryptography.

use crate::error::Result;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Trait for Key Encapsulation Mechanism (KEM) with domain-specific types
pub trait Kem {
    /// Public key type with appropriate constraints
    type PublicKey: AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Secret key type with security guarantees
    type SecretKey: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Shared secret type with security guarantees
    type SharedSecret: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Ciphertext type for the encapsulated key
    type Ciphertext: AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Keypair type for efficient storage of related keys
    type KeyPair: Clone;
    
    /// Returns the KEM algorithm name
    fn name() -> &'static str;
    
    /// Generate a new keypair
    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R
    ) -> Result<Self::KeyPair>;
    
    /// Extract public key from keypair
    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey;
    
    /// Extract secret key from keypair
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey;
    
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