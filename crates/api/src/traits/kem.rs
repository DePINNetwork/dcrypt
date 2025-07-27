//! Trait definition for Key Encapsulation Mechanisms (KEM) with enhanced type safety
//!
//! This module provides a type-safe interface for key encapsulation mechanisms,
//! which are used for secure key exchange in public-key cryptography.
//!
//! # Security Improvements
//! 
//! This trait has been hardened by removing direct byte access:
//! - No `AsMut<[u8]>` - prevents key tampering and corruption
//! - No `AsRef<[u8]>` - prevents accidental key exposure
//! - All byte access must go through explicit, auditable methods

use crate::Result;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Trait for Key Encapsulation Mechanism (KEM) with domain-specific types
/// 
/// # Security Design
/// 
/// Types are opaque - no direct byte access is provided to prevent:
/// - Key manipulation attacks (no `AsMut`)
/// - Accidental key leakage (no `AsRef`)
/// - Timing side channels through direct memory access
pub trait Kem {
    /// Public key type with appropriate constraints
    /// 
    /// # Security Note
    /// No direct byte access. Keys are opaque types that can only be
    /// used through KEM operations or explicit serialization methods.
    type PublicKey: Clone;

    /// Secret key type with security guarantees
    /// 
    /// # Security Note
    /// - Must implement `Zeroize` for secure cleanup
    /// - No direct byte access prevents accidental exposure
    /// - Can only be used through KEM operations
    type SecretKey: Zeroize + Clone;

    /// Shared secret type with security guarantees
    /// 
    /// # Security Note
    /// - Must implement `Zeroize` for secure cleanup  
    /// - No direct byte access prevents leakage
    /// - Should be converted to application keys immediately
    type SharedSecret: Zeroize + Clone;

    /// Ciphertext type for the encapsulated key
    /// 
    /// # Security Note
    /// No direct byte access prevents tampering.
    /// Modifications would invalidate the encapsulation.
    type Ciphertext: Clone;

    /// Keypair type for efficient storage of related keys
    type KeyPair: Clone;

    /// Returns the KEM algorithm name
    fn name() -> &'static str;

    /// Generate a new keypair
    /// 
    /// # Security Requirements
    /// - Must use the provided CSPRNG for all randomness
    /// - Keys must be generated according to the algorithm specification
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::KeyPair>;

    /// Extract public key from keypair
    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey;

    /// Extract secret key from keypair
    /// 
    /// # Security Note
    /// The returned secret key should be protected and zeroized after use
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey;

    /// Encapsulate a shared secret using the recipient's public key
    /// 
    /// # Security Requirements
    /// - Must validate the public key internally
    /// - Must use fresh randomness from the provided RNG
    /// - Must be resistant to side-channel attacks
    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)>;

    /// Decapsulate a shared secret using the private key
    /// 
    /// # Security Requirements
    /// - Must be constant-time
    /// - Should use implicit rejection for IND-CCA2 security
    /// - Must not leak information about the secret key
    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret>;
}