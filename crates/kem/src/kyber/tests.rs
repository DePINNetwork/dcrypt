// kem/src/kyber/tests.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::{Kyber512, Kyber768, Kyber1024};
    use api::Kem;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_kyber512_keygen() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let result = Kyber512::keypair(&mut rng);
        assert!(result.is_ok());
        
        let (pk, sk) = result.unwrap();
        assert_eq!(pk.as_ref().len(), 800);  // Kyber512 public key size
        assert_eq!(sk.as_ref().len(), 1632); // Kyber512 secret key size
    }

    #[test]
    fn test_kyber768_keygen() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let result = Kyber768::keypair(&mut rng);
        assert!(result.is_ok());
        
        let (pk, sk) = result.unwrap();
        assert_eq!(pk.as_ref().len(), 1184); // Kyber768 public key size
        assert_eq!(sk.as_ref().len(), 2400); // Kyber768 secret key size
    }

    #[test]
    fn test_kyber1024_keygen() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let result = Kyber1024::keypair(&mut rng);
        assert!(result.is_ok());
        
        let (pk, sk) = result.unwrap();
        assert_eq!(pk.as_ref().len(), 1568); // Kyber1024 public key size
        assert_eq!(sk.as_ref().len(), 3168); // Kyber1024 secret key size
    }

    #[test]
    fn test_kyber512_encaps_decaps() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        
        // Generate keypair
        let (pk, sk) = Kyber512::keypair(&mut rng).unwrap();
        
        // Encapsulate
        let (ct, ss1) = Kyber512::encapsulate(&mut rng, &pk).unwrap();
        assert_eq!(ct.as_ref().len(), 768); // Kyber512 ciphertext size
        assert_eq!(ss1.as_ref().len(), 32);  // Shared secret size
        
        // Decapsulate
        let ss2 = Kyber512::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss2.as_ref().len(), 32);
        
        // Shared secrets should match
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_kyber768_encaps_decaps() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        
        // Generate keypair
        let (pk, sk) = Kyber768::keypair(&mut rng).unwrap();
        
        // Encapsulate
        let (ct, ss1) = Kyber768::encapsulate(&mut rng, &pk).unwrap();
        assert_eq!(ct.as_ref().len(), 1088); // Kyber768 ciphertext size
        assert_eq!(ss1.as_ref().len(), 32);   // Shared secret size
        
        // Decapsulate
        let ss2 = Kyber768::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss2.as_ref().len(), 32);
        
        // Shared secrets should match
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_kyber1024_encaps_decaps() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        
        // Generate keypair
        let (pk, sk) = Kyber1024::keypair(&mut rng).unwrap();
        
        // Encapsulate
        let (ct, ss1) = Kyber1024::encapsulate(&mut rng, &pk).unwrap();
        assert_eq!(ct.as_ref().len(), 1568); // Kyber1024 ciphertext size
        assert_eq!(ss1.as_ref().len(), 32);   // Shared secret size
        
        // Decapsulate
        let ss2 = Kyber1024::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss2.as_ref().len(), 32);
        
        // Shared secrets should match
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_invalid_ciphertext() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        
        // Generate keypair
        let (pk, sk) = Kyber512::keypair(&mut rng).unwrap();
        
        // Create valid ciphertext
        let (mut ct, _) = Kyber512::encapsulate(&mut rng, &pk).unwrap();
        
        // Corrupt the ciphertext
        ct.as_mut()[0] ^= 0xFF;
        
        // Decapsulation should still succeed (IND-CCA2)
        let result = Kyber512::decapsulate(&sk, &ct);
        assert!(result.is_ok());
        
        // But the shared secret will be different (implicitly)
    }

    #[test]
    fn test_wrong_key_sizes() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        
        // Create keys with wrong sizes using the public new methods
        let bad_pk = crate::kyber::KyberPublicKey::new(vec![0u8; 100]); // Wrong size
        let bad_sk = crate::kyber::KyberSecretKey::new(vec![0u8; 100]); // Wrong size
        let bad_ct = crate::kyber::KyberCiphertext::new(vec![0u8; 100]); // Wrong size
        
        // Encapsulation with wrong-sized public key should fail
        let result = Kyber512::encapsulate(&mut rng, &bad_pk);
        assert!(result.is_err());
        
        // Decapsulation with wrong-sized secret key should fail
        let (pk, _) = Kyber512::keypair(&mut rng).unwrap();
        let (ct, _) = Kyber512::encapsulate(&mut rng, &pk).unwrap();
        let result = Kyber512::decapsulate(&bad_sk, &ct);
        assert!(result.is_err());
        
        // Decapsulation with wrong-sized ciphertext should fail
        let (_, sk) = Kyber512::keypair(&mut rng).unwrap();
        let result = Kyber512::decapsulate(&sk, &bad_ct);
        assert!(result.is_err());
    }

    // Test vectors from NIST (simplified - in production use full KAT vectors)
    #[test]
    fn test_kyber512_kat_simple() {
        // This is a simplified test - in production, use full NIST KAT vectors
        let seed = [0u8; 48]; // d || z from KAT
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        
        // Generate deterministic keypair
        let (pk, sk) = Kyber512::keypair(&mut rng).unwrap();
        
        // Verify key sizes
        assert_eq!(pk.as_ref().len(), 800);
        assert_eq!(sk.as_ref().len(), 1632);
    }
}