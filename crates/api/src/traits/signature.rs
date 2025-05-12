//! Trait definition for digital signature schemes with enhanced type safety
//!
//! This module provides a type-safe interface for digital signature schemes,
//! with strong typing for keys and signatures.

use crate::Result;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Trait for digital signature schemes with domain-specific types
pub trait Signature {
    /// Public key type
    type PublicKey: AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Secret key type with security guarantees
    type SecretKey: Zeroize + AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Signature type
    type SignatureData: AsRef<[u8]> + AsMut<[u8]> + Clone;
    
    /// Keypair type for efficient storage of related keys
    type KeyPair: Clone;
    
    /// Returns the signature algorithm name
    fn name() -> &'static str;
    
    /// Generate a new keypair
    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R
    ) -> Result<Self::KeyPair>;
    
    /// Extract public key from keypair
    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey;
    
    /// Extract secret key from keypair
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey;
    
    /// Sign a message using the secret key
    fn sign(
        message: &[u8],
        secret_key: &Self::SecretKey,
    ) -> Result<Self::SignatureData>;
    
    /// Verify a signature on a message using the public key
    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> Result<()>;
    
    /// Sign multiple messages in batch (may be more efficient for some algorithms)
    fn batch_sign(
        messages: &[&[u8]],
        secret_key: &Self::SecretKey,
    ) -> Result<Vec<Self::SignatureData>> {
        // Default implementation just calls sign for each message
        messages.iter()
            .map(|message| Self::sign(message, secret_key))
            .collect()
    }
    
    /// Verify multiple signatures in batch (may be more efficient for some algorithms)
    fn batch_verify(
        message_signature_pairs: &[(&[u8], &Self::SignatureData)],
        public_key: &Self::PublicKey,
    ) -> Result<()> {
        // Default implementation just calls verify for each pair
        for (message, signature) in message_signature_pairs {
            Self::verify(message, signature, public_key)?;
        }
        Ok(())
    }
}