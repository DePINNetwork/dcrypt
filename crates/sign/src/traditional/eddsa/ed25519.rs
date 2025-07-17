//! Ed25519 signature scheme implementation
//!
//! This is a complete implementation of Ed25519 as specified in RFC 8032,
//! with full Curve25519 arithmetic operations included.

use super::constants::{ED25519_PUBLIC_KEY_SIZE, ED25519_SECRET_KEY_SIZE, ED25519_SIGNATURE_SIZE};
use api::{Signature as SignatureTrait, Result as ApiResult, error::Error as ApiError};
use zeroize::Zeroize;
use rand::{CryptoRng, RngCore};
use algorithms::hash::sha2::Sha512;
use algorithms::hash::HashFunction;
use internal::constant_time::ct_eq;

// Import curve operations from the refactored modules
use super::operations;

/// Ed25519 signature scheme
pub struct Ed25519;

/// Ed25519 public key (32 bytes)
#[derive(Clone, Zeroize)]
pub struct Ed25519PublicKey(pub [u8; ED25519_PUBLIC_KEY_SIZE]);

/// Ed25519 expanded secret key
#[derive(Clone)]
pub struct Ed25519SecretKey {
    /// The original 32-byte seed
    seed: [u8; ED25519_SECRET_KEY_SIZE],
    /// The expanded key material (64 bytes from SHA-512)
    expanded: [u8; 64],
}

impl Zeroize for Ed25519SecretKey {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.expanded.zeroize();
    }
}

impl Drop for Ed25519SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Ed25519 signature (64 bytes: R || s)
#[derive(Clone, Zeroize)]
pub struct Ed25519Signature(pub [u8; ED25519_SIGNATURE_SIZE]);

// AsRef/AsMut implementations for byte access
impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl AsMut<[u8]> for Ed25519PublicKey {
    fn as_mut(&mut self) -> &mut [u8] { &mut self.0 }
}

impl AsRef<[u8]> for Ed25519SecretKey {
    fn as_ref(&self) -> &[u8] { &self.seed }
}

impl AsMut<[u8]> for Ed25519SecretKey {
    fn as_mut(&mut self) -> &mut [u8] { &mut self.seed }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl AsMut<[u8]> for Ed25519Signature {
    fn as_mut(&mut self) -> &mut [u8] { &mut self.0 }
}

impl SignatureTrait for Ed25519 {
    type PublicKey = Ed25519PublicKey;
    type SecretKey = Ed25519SecretKey;
    type SignatureData = Ed25519Signature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str { "Ed25519" }

    /// Generate an Ed25519 key pair
    /// 
    /// This follows the key generation process from RFC 8032:
    /// 1. Generate a 32-byte random seed
    /// 2. Hash the seed with SHA-512 to get 64 bytes
    /// 3. Clear/set specific bits in the first 32 bytes (scalar clamping)
    /// 4. Use the clamped scalar to derive the public key
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        // Step 1: Generate random 32-byte seed
        let mut seed = [0u8; ED25519_SECRET_KEY_SIZE];
        rng.fill_bytes(&mut seed);
        
        // Step 2: Expand seed using SHA-512
        let mut hasher = Sha512::new();
        hasher.update(&seed)
            .map_err(|e| ApiError::from(e))?;
        let hash = hasher.finalize()
            .map_err(|e| ApiError::from(e))?;
        
        let mut expanded = [0u8; 64];
        expanded.copy_from_slice(hash.as_ref());
        
        // Step 3: Apply Ed25519 clamping to scalar (first 32 bytes)
        expanded[0] &= 248;  // Clear bits 0, 1, 2
        expanded[31] &= 127; // Clear bit 255
        expanded[31] |= 64;  // Set bit 254
        
        // Step 4: Derive public key A = [scalar]B
        let mut public_key = [0u8; ED25519_PUBLIC_KEY_SIZE];
        operations::derive_public_key(&expanded[0..32], &mut public_key)
            .map_err(|e| ApiError::InvalidParameter {
                context: "Ed25519 keypair generation",
                #[cfg(feature = "std")]
                message: format!("Failed to derive public key: {}", e),
            })?;
        
        Ok((
            Ed25519PublicKey(public_key),
            Ed25519SecretKey { seed, expanded }
        ))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    /// Sign a message using Ed25519
    /// 
    /// The signing process follows RFC 8032:
    /// 1. r = SHA-512(prefix || message) mod L
    /// 2. R = [r]B
    /// 3. k = SHA-512(R || A || message) mod L
    /// 4. s = (r + k*a) mod L
    /// 5. Return (R, s)
    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> ApiResult<Self::SignatureData> {
        // Extract scalar and prefix from expanded secret key
        let scalar = &secret_key.expanded[0..32];
        let prefix = &secret_key.expanded[32..64];
        
        // Step 1: Compute r = SHA-512(prefix || message) mod L
        let mut hasher = Sha512::new();
        hasher.update(prefix)
            .map_err(|e| ApiError::from(e))?;
        hasher.update(message)
            .map_err(|e| ApiError::from(e))?;
        let r_hash = hasher.finalize()
            .map_err(|e| ApiError::from(e))?;
        
        let mut r = [0u8; 32];
        operations::reduce_512_to_scalar(r_hash.as_ref(), &mut r);
        
        // Step 2: Compute R = [r]B
        let r_point = operations::scalar_mult_base(&r);
        
        // Step 3: Get public key A (we recompute it, but could cache)
        let mut public_key = [0u8; 32];
        operations::derive_public_key(scalar, &mut public_key)
            .map_err(|e| ApiError::InvalidParameter {
                context: "Ed25519 signing",
                #[cfg(feature = "std")]
                message: format!("Failed to derive public key: {}", e),
            })?;
        
        // Step 4: Compute k = SHA-512(R || A || message) mod L
        let mut hasher = Sha512::new();
        hasher.update(&r_point)
            .map_err(|e| ApiError::from(e))?;
        hasher.update(&public_key)
            .map_err(|e| ApiError::from(e))?;
        hasher.update(message)
            .map_err(|e| ApiError::from(e))?;
        let k_hash = hasher.finalize()
            .map_err(|e| ApiError::from(e))?;
        
        let mut k = [0u8; 32];
        operations::reduce_512_to_scalar(k_hash.as_ref(), &mut k);
        
        // Step 5: Compute s = (r + k*a) mod L
        let mut s = [0u8; 32];
        operations::compute_s(&r, &k, scalar, &mut s);
        
        // Step 6: Construct signature (R || s)
        let mut signature = [0u8; ED25519_SIGNATURE_SIZE];
        signature[0..32].copy_from_slice(&r_point);
        signature[32..64].copy_from_slice(&s);
        
        Ok(Ed25519Signature(signature))
    }

    /// Verify an Ed25519 signature
    /// 
    /// The verification process checks that:
    /// [s]B = R + [k]A
    /// where k = SHA-512(R || A || message) mod L
    fn verify(message: &[u8], signature: &Self::SignatureData, public_key: &Self::PublicKey) -> ApiResult<()> {
        // Input validation
        if public_key.0.len() != ED25519_PUBLIC_KEY_SIZE {
            return Err(ApiError::InvalidKey {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: "Invalid public key size".to_string(),
            });
        }
        
        if signature.0.len() != ED25519_SIGNATURE_SIZE {
            return Err(ApiError::InvalidSignature {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: "Invalid signature size".to_string(),
            });
        }
        
        // Parse signature as (R, s)
        let r_bytes = &signature.0[0..32];
        let s_bytes = &signature.0[32..64];
        
        // Basic validation: s should not be all zeros
        if s_bytes.iter().all(|&b| b == 0) {
            return Err(ApiError::InvalidSignature {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: "Invalid s value in signature (all zeros)".to_string(),
            });
        }
        
        // Compute k = SHA-512(R || A || message) mod L
        let mut hasher = Sha512::new();
        hasher.update(r_bytes)
            .map_err(|e| ApiError::from(e))?;
        hasher.update(&public_key.0)
            .map_err(|e| ApiError::from(e))?;
        hasher.update(message)
            .map_err(|e| ApiError::from(e))?;
        let k_hash = hasher.finalize()
            .map_err(|e| ApiError::from(e))?;
        
        let mut k = [0u8; 32];
        operations::reduce_512_to_scalar(k_hash.as_ref(), &mut k);
        
        // Verify the signature equation: [s]B = R + [k]A
        let mut check = [0u8; 32];
        operations::verify_equation(s_bytes, r_bytes, &k, &public_key.0, &mut check)
            .map_err(|e| ApiError::InvalidSignature {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: format!("Signature verification failed: {}", e),
            })?;
        
        // Check result using constant-time comparison
        if !ct_eq(&check, &[1u8; 32]) {
            return Err(ApiError::InvalidSignature {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: "Signature verification equation failed".to_string(),
            });
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_ed25519_keypair_generation() {
        let mut rng = OsRng;
        let result = Ed25519::keypair(&mut rng);
        assert!(result.is_ok(), "Keypair generation failed: {:?}", result.err());
        
        let (public_key, secret_key) = result.unwrap();
        assert_eq!(public_key.0.len(), ED25519_PUBLIC_KEY_SIZE);
        assert_eq!(secret_key.seed.len(), ED25519_SECRET_KEY_SIZE);
        assert_eq!(secret_key.expanded.len(), 64);
        
        // Verify clamping was applied correctly
        assert_eq!(secret_key.expanded[0] & 7, 0, "Low 3 bits should be cleared");
        assert_eq!(secret_key.expanded[31] & 128, 0, "Bit 255 should be cleared");
        assert_eq!(secret_key.expanded[31] & 64, 64, "Bit 254 should be set");
    }

    #[test]
    fn test_ed25519_sign() {
        let mut rng = OsRng;
        let (_, secret_key) = Ed25519::keypair(&mut rng).unwrap();
        
        let message = b"Test message for signing";
        let result = Ed25519::sign(message, &secret_key);
        assert!(result.is_ok(), "Signing failed: {:?}", result.err());
        
        let signature = result.unwrap();
        assert_eq!(signature.0.len(), ED25519_SIGNATURE_SIZE);
        
        // Check that R and s are not all zeros
        let r = &signature.0[0..32];
        let s = &signature.0[32..64];
        assert!(!r.iter().all(|&b| b == 0), "R should not be all zeros");
        assert!(!s.iter().all(|&b| b == 0), "s should not be all zeros");
    }

    #[test]
    fn test_ed25519_sign_verify_cycle() {
        let mut rng = OsRng;
        let (public_key, secret_key) = Ed25519::keypair(&mut rng).unwrap();
        
        let message = b"Complete test message for Ed25519 sign/verify cycle";
        
        // Sign the message
        let signature = Ed25519::sign(message, &secret_key)
            .expect("Signing should succeed");
        
        // Verify the signature
        let result = Ed25519::verify(message, &signature, &public_key);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    #[test]
    fn test_ed25519_deterministic_signatures() {
        let mut rng = OsRng;
        let (_, secret_key) = Ed25519::keypair(&mut rng).unwrap();
        
        let message = b"Test for deterministic signatures";
        
        // Sign the same message twice
        let sig1 = Ed25519::sign(message, &secret_key).unwrap();
        let sig2 = Ed25519::sign(message, &secret_key).unwrap();
        
        // Signatures should be identical
        assert_eq!(sig1.0, sig2.0, "Ed25519 signatures must be deterministic");
    }

    #[test]
    fn test_ed25519_different_messages_different_signatures() {
        let mut rng = OsRng;
        let (public_key, secret_key) = Ed25519::keypair(&mut rng).unwrap();
        
        let msg1 = b"First message";
        let msg2 = b"Second message";
        
        let sig1 = Ed25519::sign(msg1, &secret_key).unwrap();
        let sig2 = Ed25519::sign(msg2, &secret_key).unwrap();
        
        // Signatures should be different
        assert_ne!(sig1.0, sig2.0, "Different messages must produce different signatures");
        
        // Both should verify correctly
        assert!(Ed25519::verify(msg1, &sig1, &public_key).is_ok());
        assert!(Ed25519::verify(msg2, &sig2, &public_key).is_ok());
        
        // Cross-verification should fail
        assert!(Ed25519::verify(msg1, &sig2, &public_key).is_err(), "Wrong signature should fail");
        assert!(Ed25519::verify(msg2, &sig1, &public_key).is_err(), "Wrong signature should fail");
    }

    #[test]
    fn test_ed25519_wrong_public_key_fails() {
        let mut rng = OsRng;
        let (_, secret_key1) = Ed25519::keypair(&mut rng).unwrap();
        let (public_key2, _) = Ed25519::keypair(&mut rng).unwrap();
        
        let message = b"Test message";
        let signature = Ed25519::sign(message, &secret_key1).unwrap();
        
        // Verification with wrong public key should fail
        let result = Ed25519::verify(message, &signature, &public_key2);
        assert!(result.is_err(), "Verification with wrong public key should fail");
    }

    #[test]
    fn test_ed25519_empty_message() {
        let mut rng = OsRng;
        let (public_key, secret_key) = Ed25519::keypair(&mut rng).unwrap();
        
        let message = b"";
        let signature = Ed25519::sign(message, &secret_key).unwrap();
        
        assert!(Ed25519::verify(message, &signature, &public_key).is_ok(),
                "Empty message should sign and verify correctly");
    }

    #[test]
    fn test_ed25519_invalid_signatures() {
        let mut rng = OsRng;
        let (public_key, _) = Ed25519::keypair(&mut rng).unwrap();
        
        let message = b"Test message";
        
        // Test 1: All-zero signature
        let zero_sig = Ed25519Signature([0u8; ED25519_SIGNATURE_SIZE]);
        assert!(Ed25519::verify(message, &zero_sig, &public_key).is_err(),
                "All-zero signature should fail");
        
        // Test 2: Random invalid signature
        let mut random_sig = Ed25519Signature([0u8; ED25519_SIGNATURE_SIZE]);
        rng.fill_bytes(&mut random_sig.0);
        assert!(Ed25519::verify(message, &random_sig, &public_key).is_err(),
                "Random signature should fail");
        
        // Test 3: Malformed signature (wrong size would be caught by type system)
        // So we test a signature with invalid s value (all zeros in s part)
        let mut invalid_s_sig = Ed25519Signature([0u8; ED25519_SIGNATURE_SIZE]);
        rng.fill_bytes(&mut invalid_s_sig.0[0..32]); // Random R
        // s part stays all zeros
        assert!(Ed25519::verify(message, &invalid_s_sig, &public_key).is_err(),
                "Signature with zero s should fail");
    }

    #[test]
    fn test_ed25519_signature_malleability_resistance() {
        let mut rng = OsRng;
        let (public_key, secret_key) = Ed25519::keypair(&mut rng).unwrap();
        
        let message = b"Test malleability";
        let signature = Ed25519::sign(message, &secret_key).unwrap();
        
        // Try to create a malleable signature by modifying s
        // (In a proper implementation, this should fail verification)
        let mut malleable_sig = signature.clone();
        malleable_sig.0[32] ^= 0x01; // Flip one bit in s
        
        assert!(Ed25519::verify(message, &malleable_sig, &public_key).is_err(),
                "Modified signature should fail verification");
    }
}