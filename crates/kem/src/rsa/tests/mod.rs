//! Unit tests for RSA-KEM implementations

use api::Kem;
use rand::rngs::OsRng;

#[cfg(test)]
mod rsa2048_tests {
    use super::*;
    use crate::rsa::{RsaKem2048, RsaPublicKey, RsaSecretKey};

    #[test]
    fn test_keypair_generation() {
        let mut rng = OsRng;
        let result = RsaKem2048::keypair(&mut rng);
        
        assert!(result.is_ok(), "Key generation should succeed");
        
        let (public_key, secret_key) = result.unwrap();
        
        // Check modulus size (2048 bits = 256 bytes)
        assert_eq!(public_key.modulus.len(), 256, "Public key modulus should be 256 bytes");
        assert_eq!(secret_key.modulus.len(), 256, "Secret key modulus should be 256 bytes");
        
        // Check public exponent (should be 65537 = 0x010001)
        assert_eq!(public_key.exponent.len(), 3, "Public exponent should be 3 bytes");
        assert_eq!(public_key.exponent[0], 0x01);
        assert_eq!(public_key.exponent[1], 0x00);
        assert_eq!(public_key.exponent[2], 0x01);
        
        // Check private exponent size
        assert_eq!(secret_key.private_exponent.len(), 256, "Private exponent should be 256 bytes");
        
        // Ensure keys are not all zeros
        assert!(public_key.modulus.iter().any(|&b| b != 0), "Public key modulus should not be all zeros");
        assert!(secret_key.private_exponent.iter().any(|&b| b != 0), "Private exponent should not be all zeros");
    }

    #[test]
    fn test_public_key_extraction() {
        let mut rng = OsRng;
        let keypair = RsaKem2048::keypair(&mut rng).unwrap();
        let public_key = RsaKem2048::public_key(&keypair);
        
        // Verify extracted public key matches original
        assert_eq!(public_key.modulus, keypair.0.modulus);
        assert_eq!(public_key.exponent, keypair.0.exponent);
    }

    #[test]
    fn test_secret_key_extraction() {
        let mut rng = OsRng;
        let keypair = RsaKem2048::keypair(&mut rng).unwrap();
        let secret_key = RsaKem2048::secret_key(&keypair);
        
        // Verify extracted secret key matches original
        assert_eq!(secret_key.modulus, keypair.1.modulus);
        assert_eq!(secret_key.private_exponent, keypair.1.private_exponent);
    }

    #[test]
    fn test_encapsulation() {
        let mut rng = OsRng;
        let keypair = RsaKem2048::keypair(&mut rng).unwrap();
        let public_key = RsaKem2048::public_key(&keypair);
        
        let result = RsaKem2048::encapsulate(&mut rng, &public_key);
        assert!(result.is_ok(), "Encapsulation should succeed");
        
        let (ciphertext, shared_secret) = result.unwrap();
        
        // Check ciphertext size (should match modulus size)
        assert_eq!(ciphertext.as_ref().len(), 256, "Ciphertext should be 256 bytes");
        
        // Check shared secret size (defined as BASE_KEY_SIZE = 32)
        assert_eq!(shared_secret.as_ref().len(), 32, "Shared secret should be 32 bytes");
        
        // Ensure outputs are not all zeros
        assert!(ciphertext.as_ref().iter().any(|&b| b != 0), "Ciphertext should not be all zeros");
        assert!(shared_secret.as_ref().iter().any(|&b| b != 0), "Shared secret should not be all zeros");
    }

    #[test]
    fn test_decapsulation() {
        let mut rng = OsRng;
        let keypair = RsaKem2048::keypair(&mut rng).unwrap();
        let public_key = RsaKem2048::public_key(&keypair);
        let secret_key = RsaKem2048::secret_key(&keypair);
        
        // Encapsulate
        let (ciphertext, _) = RsaKem2048::encapsulate(&mut rng, &public_key).unwrap();
        
        // Decapsulate
        let result = RsaKem2048::decapsulate(&secret_key, &ciphertext);
        assert!(result.is_ok(), "Decapsulation should succeed");
        
        let decapsulated_secret = result.unwrap();
        assert_eq!(decapsulated_secret.as_ref().len(), 32, "Decapsulated secret should be 32 bytes");
    }

    #[test]
    fn test_invalid_public_key_modulus_size() {
        let mut rng = OsRng;
        
        // Create invalid public key with wrong modulus size
        let invalid_public_key = RsaPublicKey {
            modulus: vec![0u8; 128], // Wrong size (should be 256)
            exponent: vec![0x01, 0x00, 0x01],
        };
        
        let result = RsaKem2048::encapsulate(&mut rng, &invalid_public_key);
        assert!(result.is_err(), "Encapsulation should fail with wrong modulus size");
    }

    #[test]
    fn test_invalid_public_key_all_zeros() {
        let mut rng = OsRng;
        
        // Create invalid public key with all-zero modulus
        let invalid_public_key = RsaPublicKey {
            modulus: vec![0u8; 256],
            exponent: vec![0x01, 0x00, 0x01],
        };
        
        let result = RsaKem2048::encapsulate(&mut rng, &invalid_public_key);
        assert!(result.is_err(), "Encapsulation should fail with all-zero modulus");
    }

    #[test]
    fn test_invalid_ciphertext_size() {
        let mut rng = OsRng;
        let keypair = RsaKem2048::keypair(&mut rng).unwrap();
        let secret_key = RsaKem2048::secret_key(&keypair);
        
        // Create invalid ciphertext with wrong size
        let invalid_ciphertext = super::super::common::RsaCiphertext(vec![0u8; 128]); // Wrong size
        
        let result = RsaKem2048::decapsulate(&secret_key, &invalid_ciphertext);
        assert!(result.is_err(), "Decapsulation should fail with wrong ciphertext size");
    }

    #[test]
    fn test_invalid_secret_key_modulus_size() {
        let mut rng = OsRng;
        let keypair = RsaKem2048::keypair(&mut rng).unwrap();
        let public_key = RsaKem2048::public_key(&keypair);
        let (ciphertext, _) = RsaKem2048::encapsulate(&mut rng, &public_key).unwrap();
        
        // Create invalid secret key with wrong modulus size
        let invalid_secret_key = RsaSecretKey {
            modulus: vec![0u8; 128], // Wrong size
            private_exponent: vec![0u8; 256],
        };
        
        let result = RsaKem2048::decapsulate(&invalid_secret_key, &ciphertext);
        assert!(result.is_err(), "Decapsulation should fail with wrong modulus size");
    }

    #[test]
    fn test_invalid_secret_key_exponent_size() {
        let mut rng = OsRng;
        let keypair = RsaKem2048::keypair(&mut rng).unwrap();
        let public_key = RsaKem2048::public_key(&keypair);
        let (ciphertext, _) = RsaKem2048::encapsulate(&mut rng, &public_key).unwrap();
        
        // Create invalid secret key with wrong exponent size
        let invalid_secret_key = RsaSecretKey {
            modulus: vec![0u8; 256],
            private_exponent: vec![0u8; 128], // Wrong size
        };
        
        let result = RsaKem2048::decapsulate(&invalid_secret_key, &ciphertext);
        assert!(result.is_err(), "Decapsulation should fail with wrong exponent size");
    }

    #[test]
    fn test_multiple_encapsulations_different_secrets() {
        let mut rng = OsRng;
        let keypair = RsaKem2048::keypair(&mut rng).unwrap();
        let public_key = RsaKem2048::public_key(&keypair);
        
        // Perform multiple encapsulations
        let (ct1, ss1) = RsaKem2048::encapsulate(&mut rng, &public_key).unwrap();
        let (ct2, ss2) = RsaKem2048::encapsulate(&mut rng, &public_key).unwrap();
        
        // Ciphertexts should be different
        assert_ne!(ct1.as_ref(), ct2.as_ref(), "Different encapsulations should produce different ciphertexts");
        
        // Shared secrets should be different
        assert_ne!(ss1.as_ref(), ss2.as_ref(), "Different encapsulations should produce different shared secrets");
    }

    #[test]
    fn test_key_trait_implementations() {
        let mut rng = OsRng;
        let keypair = RsaKem2048::keypair(&mut rng).unwrap();
        let (public_key, secret_key) = keypair;
        
        // Test AsRef trait
        let pk_ref: &[u8] = public_key.as_ref();
        assert_eq!(pk_ref.len(), 256);
        
        let sk_ref: &[u8] = secret_key.as_ref();
        assert_eq!(sk_ref.len(), 256);
        
        // Test AsMut trait
        let mut pk_clone = public_key.clone();
        let pk_mut: &mut [u8] = pk_clone.as_mut();
        assert_eq!(pk_mut.len(), 256);
        
        let mut sk_clone = secret_key.clone();
        let sk_mut: &mut [u8] = sk_clone.as_mut();
        assert_eq!(sk_mut.len(), 256);
    }

    #[test]
    fn test_algorithm_name() {
        assert_eq!(RsaKem2048::name(), "RSA-2048");
    }
}

#[cfg(test)]
mod rsa4096_tests {
    use super::*;
    use crate::rsa::{RsaKem4096, RsaPublicKey, RsaSecretKey};

    #[test]
    fn test_keypair_generation() {
        let mut rng = OsRng;
        let result = RsaKem4096::keypair(&mut rng);
        
        assert!(result.is_ok(), "Key generation should succeed");
        
        let (public_key, secret_key) = result.unwrap();
        
        // Check modulus size (4096 bits = 512 bytes)
        assert_eq!(public_key.modulus.len(), 512, "Public key modulus should be 512 bytes");
        assert_eq!(secret_key.modulus.len(), 512, "Secret key modulus should be 512 bytes");
        
        // Check public exponent (should be 65537 = 0x010001)
        assert_eq!(public_key.exponent.len(), 3, "Public exponent should be 3 bytes");
        assert_eq!(public_key.exponent[0], 0x01);
        assert_eq!(public_key.exponent[1], 0x00);
        assert_eq!(public_key.exponent[2], 0x01);
        
        // Check private exponent size
        assert_eq!(secret_key.private_exponent.len(), 512, "Private exponent should be 512 bytes");
        
        // Ensure keys are not all zeros
        assert!(public_key.modulus.iter().any(|&b| b != 0), "Public key modulus should not be all zeros");
        assert!(secret_key.private_exponent.iter().any(|&b| b != 0), "Private exponent should not be all zeros");
    }

    #[test]
    fn test_public_key_extraction() {
        let mut rng = OsRng;
        let keypair = RsaKem4096::keypair(&mut rng).unwrap();
        let public_key = RsaKem4096::public_key(&keypair);
        
        // Verify extracted public key matches original
        assert_eq!(public_key.modulus, keypair.0.modulus);
        assert_eq!(public_key.exponent, keypair.0.exponent);
    }

    #[test]
    fn test_secret_key_extraction() {
        let mut rng = OsRng;
        let keypair = RsaKem4096::keypair(&mut rng).unwrap();
        let secret_key = RsaKem4096::secret_key(&keypair);
        
        // Verify extracted secret key matches original
        assert_eq!(secret_key.modulus, keypair.1.modulus);
        assert_eq!(secret_key.private_exponent, keypair.1.private_exponent);
    }

    #[test]
    fn test_encapsulation() {
        let mut rng = OsRng;
        let keypair = RsaKem4096::keypair(&mut rng).unwrap();
        let public_key = RsaKem4096::public_key(&keypair);
        
        let result = RsaKem4096::encapsulate(&mut rng, &public_key);
        assert!(result.is_ok(), "Encapsulation should succeed");
        
        let (ciphertext, shared_secret) = result.unwrap();
        
        // Check ciphertext size (should match modulus size)
        assert_eq!(ciphertext.as_ref().len(), 512, "Ciphertext should be 512 bytes");
        
        // Check shared secret size (defined as BASE_KEY_SIZE = 32)
        assert_eq!(shared_secret.as_ref().len(), 32, "Shared secret should be 32 bytes");
        
        // Ensure outputs are not all zeros
        assert!(ciphertext.as_ref().iter().any(|&b| b != 0), "Ciphertext should not be all zeros");
        assert!(shared_secret.as_ref().iter().any(|&b| b != 0), "Shared secret should not be all zeros");
    }

    #[test]
    fn test_decapsulation() {
        let mut rng = OsRng;
        let keypair = RsaKem4096::keypair(&mut rng).unwrap();
        let public_key = RsaKem4096::public_key(&keypair);
        let secret_key = RsaKem4096::secret_key(&keypair);
        
        // Encapsulate
        let (ciphertext, _) = RsaKem4096::encapsulate(&mut rng, &public_key).unwrap();
        
        // Decapsulate
        let result = RsaKem4096::decapsulate(&secret_key, &ciphertext);
        assert!(result.is_ok(), "Decapsulation should succeed");
        
        let decapsulated_secret = result.unwrap();
        assert_eq!(decapsulated_secret.as_ref().len(), 32, "Decapsulated secret should be 32 bytes");
    }

    #[test]
    fn test_invalid_public_key_modulus_size() {
        let mut rng = OsRng;
        
        // Create invalid public key with wrong modulus size
        let invalid_public_key = RsaPublicKey {
            modulus: vec![0u8; 256], // Wrong size (should be 512)
            exponent: vec![0x01, 0x00, 0x01],
        };
        
        let result = RsaKem4096::encapsulate(&mut rng, &invalid_public_key);
        assert!(result.is_err(), "Encapsulation should fail with wrong modulus size");
    }

    #[test]
    fn test_invalid_public_key_all_zeros() {
        let mut rng = OsRng;
        
        // Create invalid public key with all-zero modulus
        let invalid_public_key = RsaPublicKey {
            modulus: vec![0u8; 512],
            exponent: vec![0x01, 0x00, 0x01],
        };
        
        let result = RsaKem4096::encapsulate(&mut rng, &invalid_public_key);
        assert!(result.is_err(), "Encapsulation should fail with all-zero modulus");
    }

    #[test]
    fn test_invalid_ciphertext_size() {
        let mut rng = OsRng;
        let keypair = RsaKem4096::keypair(&mut rng).unwrap();
        let secret_key = RsaKem4096::secret_key(&keypair);
        
        // Create invalid ciphertext with wrong size
        let invalid_ciphertext = super::super::common::RsaCiphertext(vec![0u8; 256]); // Wrong size
        
        let result = RsaKem4096::decapsulate(&secret_key, &invalid_ciphertext);
        assert!(result.is_err(), "Decapsulation should fail with wrong ciphertext size");
    }

    #[test]
    fn test_invalid_secret_key_modulus_size() {
        let mut rng = OsRng;
        let keypair = RsaKem4096::keypair(&mut rng).unwrap();
        let public_key = RsaKem4096::public_key(&keypair);
        let (ciphertext, _) = RsaKem4096::encapsulate(&mut rng, &public_key).unwrap();
        
        // Create invalid secret key with wrong modulus size
        let invalid_secret_key = RsaSecretKey {
            modulus: vec![0u8; 256], // Wrong size
            private_exponent: vec![0u8; 512],
        };
        
        let result = RsaKem4096::decapsulate(&invalid_secret_key, &ciphertext);
        assert!(result.is_err(), "Decapsulation should fail with wrong modulus size");
    }

    #[test]
    fn test_invalid_secret_key_exponent_size() {
        let mut rng = OsRng;
        let keypair = RsaKem4096::keypair(&mut rng).unwrap();
        let public_key = RsaKem4096::public_key(&keypair);
        let (ciphertext, _) = RsaKem4096::encapsulate(&mut rng, &public_key).unwrap();
        
        // Create invalid secret key with wrong exponent size
        let invalid_secret_key = RsaSecretKey {
            modulus: vec![0u8; 512],
            private_exponent: vec![0u8; 256], // Wrong size
        };
        
        let result = RsaKem4096::decapsulate(&invalid_secret_key, &ciphertext);
        assert!(result.is_err(), "Decapsulation should fail with wrong exponent size");
    }

    #[test]
    fn test_multiple_encapsulations_different_secrets() {
        let mut rng = OsRng;
        let keypair = RsaKem4096::keypair(&mut rng).unwrap();
        let public_key = RsaKem4096::public_key(&keypair);
        
        // Perform multiple encapsulations
        let (ct1, ss1) = RsaKem4096::encapsulate(&mut rng, &public_key).unwrap();
        let (ct2, ss2) = RsaKem4096::encapsulate(&mut rng, &public_key).unwrap();
        
        // Ciphertexts should be different
        assert_ne!(ct1.as_ref(), ct2.as_ref(), "Different encapsulations should produce different ciphertexts");
        
        // Shared secrets should be different
        assert_ne!(ss1.as_ref(), ss2.as_ref(), "Different encapsulations should produce different shared secrets");
    }

    #[test]
    fn test_key_trait_implementations() {
        let mut rng = OsRng;
        let keypair = RsaKem4096::keypair(&mut rng).unwrap();
        let (public_key, secret_key) = keypair;
        
        // Test AsRef trait
        let pk_ref: &[u8] = public_key.as_ref();
        assert_eq!(pk_ref.len(), 512);
        
        let sk_ref: &[u8] = secret_key.as_ref();
        assert_eq!(sk_ref.len(), 512);
        
        // Test AsMut trait
        let mut pk_clone = public_key.clone();
        let pk_mut: &mut [u8] = pk_clone.as_mut();
        assert_eq!(pk_mut.len(), 512);
        
        let mut sk_clone = secret_key.clone();
        let sk_mut: &mut [u8] = sk_clone.as_mut();
        assert_eq!(sk_mut.len(), 512);
    }

    #[test]
    fn test_algorithm_name() {
        assert_eq!(RsaKem4096::name(), "RSA-4096");
    }
}

#[cfg(test)]
mod common_tests {
    use crate::rsa::common::{BASE_KEY_SIZE, RsaSharedSecret, RsaCiphertext};
    use api::Key;

    #[test]
    fn test_base_key_size_constant() {
        assert_eq!(BASE_KEY_SIZE, 32, "Base key size should be 32 bytes");
    }

    #[test]
    fn test_shared_secret_traits() {
        let data = vec![0x42; BASE_KEY_SIZE];
        let shared_secret = RsaSharedSecret(Key::new(&data));
        
        // Test AsRef
        let ss_ref: &[u8] = shared_secret.as_ref();
        assert_eq!(ss_ref.len(), BASE_KEY_SIZE);
        assert_eq!(ss_ref[0], 0x42);
        
        // Test AsMut
        let mut ss_clone = shared_secret.clone();
        let ss_mut: &mut [u8] = ss_clone.as_mut();
        ss_mut[0] = 0x43;
        assert_eq!(ss_clone.as_ref()[0], 0x43);
    }

    #[test]
    fn test_ciphertext_traits() {
        let data = vec![0x42; 256];
        let ciphertext = RsaCiphertext(data.clone());
        
        // Test AsRef
        let ct_ref: &[u8] = ciphertext.as_ref();
        assert_eq!(ct_ref.len(), 256);
        assert_eq!(ct_ref[0], 0x42);
        
        // Test AsMut
        let mut ct_clone = ciphertext.clone();
        let ct_mut: &mut [u8] = ct_clone.as_mut();
        ct_mut[0] = 0x43;
        assert_eq!(ct_clone.as_ref()[0], 0x43);
    }
}