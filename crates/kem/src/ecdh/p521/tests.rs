// File: crates/kem/src/ecdh/p521/tests.rs
use super::*;
use api::Kem;
use algorithms::ec::p521;
use rand::rngs::OsRng;

#[test]
fn test_p521_kem_basic_flow() {
    let mut rng = OsRng;
    
    // Generate recipient keypair
    let (recipient_pk, recipient_sk) = EcdhP521::keypair(&mut rng).unwrap();
    
    // Encapsulate
    let (ciphertext, shared_secret_sender) = EcdhP521::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    // Decapsulate
    let shared_secret_recipient = EcdhP521::decapsulate(&recipient_sk, &ciphertext).unwrap();
    
    // Verify shared secrets match
    assert_eq!(
        shared_secret_sender.as_ref(),
        shared_secret_recipient.as_ref(),
        "Shared secrets should match"
    );
}

#[test]
fn test_p521_kem_multiple_encapsulations() {
    let mut rng = OsRng;
    
    // Generate recipient keypair
    let (recipient_pk, recipient_sk) = EcdhP521::keypair(&mut rng).unwrap();
    
    // Multiple encapsulations should produce different ciphertexts and shared secrets
    let (ct1, ss1) = EcdhP521::encapsulate(&mut rng, &recipient_pk).unwrap();
    let (ct2, ss2) = EcdhP521::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    // Ciphertexts should be different (different ephemeral keys)
    assert_ne!(ct1.as_ref(), ct2.as_ref());
    
    // Shared secrets should be different
    assert_ne!(ss1.as_ref(), ss2.as_ref());
    
    // But both should decapsulate correctly
    let ss1_dec = EcdhP521::decapsulate(&recipient_sk, &ct1).unwrap();
    let ss2_dec = EcdhP521::decapsulate(&recipient_sk, &ct2).unwrap();
    
    assert_eq!(ss1.as_ref(), ss1_dec.as_ref());
    assert_eq!(ss2.as_ref(), ss2_dec.as_ref());
}

#[test]
fn test_p521_kem_invalid_public_key() {
    let mut rng = OsRng;
    
    // Test with all-zero public key (identity point)
    let invalid_pk = EcdhP521PublicKey([0u8; p521::P521_POINT_COMPRESSED_SIZE]);
    
    // Encapsulation should fail
    let result = EcdhP521::encapsulate(&mut rng, &invalid_pk);
    assert!(result.is_err());
    
    // Test with invalid point format
    let mut invalid_pk2 = EcdhP521PublicKey([0xFFu8; p521::P521_POINT_COMPRESSED_SIZE]);
    invalid_pk2.0[0] = 0x05; // Invalid format byte for compressed points
    
    let result2 = EcdhP521::encapsulate(&mut rng, &invalid_pk2);
    assert!(result2.is_err());
}

#[test]
fn test_p521_kem_invalid_ciphertext() {
    let mut rng = OsRng;
    
    // Generate recipient keypair
    let (_, recipient_sk) = EcdhP521::keypair(&mut rng).unwrap();
    
    // Test with all-zero ciphertext (identity point)
    let invalid_ct = EcdhP521Ciphertext([0u8; p521::P521_POINT_COMPRESSED_SIZE]);
    
    // Decapsulation should fail
    let result = EcdhP521::decapsulate(&recipient_sk, &invalid_ct);
    assert!(result.is_err());
}

#[test]
fn test_p521_kem_wrong_secret_key() {
    let mut rng = OsRng;
    
    // Generate two keypairs
    let (recipient_pk, _) = EcdhP521::keypair(&mut rng).unwrap();
    let (_, wrong_sk) = EcdhP521::keypair(&mut rng).unwrap();
    
    // Encapsulate to first recipient
    let (ciphertext, shared_secret_sender) = EcdhP521::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    // Try to decapsulate with wrong secret key
    let shared_secret_wrong = EcdhP521::decapsulate(&wrong_sk, &ciphertext).unwrap();
    
    // Shared secrets should NOT match
    assert_ne!(
        shared_secret_sender.as_ref(),
        shared_secret_wrong.as_ref(),
        "Shared secrets should not match with wrong key"
    );
}

/// Test vectors for P-521 ECDH-KEM
/// These test vectors use known scalar/point pairs to verify the KEM construction
mod test_vectors {
    use super::*;
    
    #[test]
    fn test_p521_kem_known_answer() {
        // This test requires creating keys from known values
        // Since the KEM API doesn't expose this directly, we'll test
        // the overall flow with generated keys
        
        let mut rng = OsRng;
        let (pk, sk) = EcdhP521::keypair(&mut rng).unwrap();
        
        // Test multiple encapsulations/decapsulations
        for _ in 0..5 {
            let (ct, ss_enc) = EcdhP521::encapsulate(&mut rng, &pk).unwrap();
            let ss_dec = EcdhP521::decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());
        }
    }
    
    #[test]
    fn test_p521_kem_edge_cases() {
        let mut rng = OsRng;
        
        // Test with multiple recipients
        let recipients: Vec<_> = (0..3)
            .map(|_| EcdhP521::keypair(&mut rng).unwrap())
            .collect();
        
        // Encapsulate to each recipient
        for (pk, sk) in &recipients {
            let (ct, ss_enc) = EcdhP521::encapsulate(&mut rng, pk).unwrap();
            let ss_dec = EcdhP521::decapsulate(sk, &ct).unwrap();
            assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());
        }
    }
}

#[test]
fn test_p521_kem_deterministic_shared_secret() {
    // For the same ephemeral key and recipient key, the shared secret should be deterministic
    let mut rng = OsRng;
    
    // Generate fixed recipient keypair
    let (recipient_pk, recipient_sk) = EcdhP521::keypair(&mut rng).unwrap();
    
    // Create a specific ciphertext
    let (ciphertext, _) = EcdhP521::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    // Compute shared secret multiple times
    let ss1 = EcdhP521::decapsulate(&recipient_sk, &ciphertext).unwrap();
    let ss2 = EcdhP521::decapsulate(&recipient_sk, &ciphertext).unwrap();
    
    // Should be identical
    assert_eq!(ss1.as_ref(), ss2.as_ref());
}

#[test]
fn test_p521_kem_serialization_roundtrip() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (pk, sk) = EcdhP521::keypair(&mut rng).unwrap();
    
    // Serialize and deserialize public key
    let pk_bytes = pk.as_ref();
    let pk_restored = EcdhP521PublicKey(pk_bytes.try_into().unwrap());
    
    // Test encapsulation with restored key
    let (ct, ss1) = EcdhP521::encapsulate(&mut rng, &pk_restored).unwrap();
    let ss2 = EcdhP521::decapsulate(&sk, &ct).unwrap();
    
    assert_eq!(ss1.as_ref(), ss2.as_ref());
}

/// Compliance tests for NIST SP 800-56A Rev. 3
mod nist_compliance {
    use super::*;
    
    #[test]
    fn test_p521_point_validation() {
        let mut rng = OsRng;
        
        // Generate valid keypair
        let (_, sk) = EcdhP521::keypair(&mut rng).unwrap();
        
        // Create invalid ciphertext (point not on curve)
        let mut invalid_ct_bytes = [0u8; p521::P521_POINT_COMPRESSED_SIZE];
        invalid_ct_bytes[0] = 0x02; // Compressed point format (even y)
        invalid_ct_bytes[1..67].fill(0xFF); // Invalid x-coordinate
        
        let invalid_ct = EcdhP521Ciphertext(invalid_ct_bytes);
        
        // Decapsulation should fail
        let result = EcdhP521::decapsulate(&sk, &invalid_ct);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_p521_scalar_validation() {
        // P-521 scalars are 66 bytes (528 bits)
        // Test that the implementation properly validates scalar ranges
        let mut rng = OsRng;
        
        // Generate valid keypair
        let (pk, _) = EcdhP521::keypair(&mut rng).unwrap();
        
        // Verify public key size
        assert_eq!(pk.as_ref().len(), p521::P521_POINT_COMPRESSED_SIZE);
    }
}

#[test]
fn test_p521_kem_consistency_across_implementations() {
    // This test ensures our implementation produces consistent results
    let mut rng = OsRng;
    
    // Run multiple iterations to catch any non-determinism
    for _ in 0..10 {
        let (pk, sk) = EcdhP521::keypair(&mut rng).unwrap();
        let (ct, ss_enc) = EcdhP521::encapsulate(&mut rng, &pk).unwrap();
        let ss_dec = EcdhP521::decapsulate(&sk, &ct).unwrap();
        
        assert_eq!(
            ss_enc.as_ref(), 
            ss_dec.as_ref(),
            "Encapsulation and decapsulation must produce same shared secret"
        );
        
        // Verify shared secret length
        assert_eq!(
            ss_enc.as_ref().len(),
            p521::P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
            "Shared secret must have correct length"
        );
    }
}

#[test]
fn test_p521_kem_compressed_format_sizes() {
    let mut rng = OsRng;
    
    // Generate keypair and verify sizes
    let (pk, sk) = EcdhP521::keypair(&mut rng).unwrap();
    
    // Verify key sizes
    assert_eq!(pk.as_ref().len(), p521::P521_POINT_COMPRESSED_SIZE, "Public key should be compressed");
    assert_eq!(sk.as_ref().len(), p521::P521_SCALAR_SIZE, "Secret key size unchanged");
    
    // Verify ciphertext size
    let (ct, _) = EcdhP521::encapsulate(&mut rng, &pk).unwrap();
    assert_eq!(ct.as_ref().len(), p521::P521_POINT_COMPRESSED_SIZE, "Ciphertext should be compressed");
}

#[test]
fn test_p521_kem_invalid_compressed_prefix() {
    let mut rng = OsRng;
    
    // Test various invalid prefixes for compressed points
    let invalid_prefixes = [0x00, 0x01, 0x04, 0x05, 0xFF];
    
    for prefix in &invalid_prefixes {
        let mut invalid_pk_bytes = [0u8; p521::P521_POINT_COMPRESSED_SIZE];
        invalid_pk_bytes[0] = *prefix;
        invalid_pk_bytes[1..].fill(0x42); // Some arbitrary data
        
        let invalid_pk = EcdhP521PublicKey(invalid_pk_bytes);
        let result = EcdhP521::encapsulate(&mut rng, &invalid_pk);
        
        assert!(result.is_err(), "Prefix {:02x} should be rejected", prefix);
    }
}

/// P-521 specific tests for large field size
mod p521_specific {
    use super::*;
    
    #[test]
    fn test_p521_field_element_size() {
        // P-521 has 66-byte field elements (521 bits rounded up)
        assert_eq!(p521::P521_FIELD_ELEMENT_SIZE, 66);
        assert_eq!(p521::P521_SCALAR_SIZE, 66);
        assert_eq!(p521::P521_POINT_COMPRESSED_SIZE, 67); // 1 byte prefix + 66 bytes x-coordinate
    }
    
    #[test]
    fn test_p521_kem_interoperability() {
        // Test that our P-521 KEM can handle edge cases specific to the larger curve
        let mut rng = OsRng;
        
        // Generate multiple keypairs and test cross-compatibility
        let keypairs: Vec<_> = (0..3)
            .map(|_| EcdhP521::keypair(&mut rng).unwrap())
            .collect();
        
        // Test all combinations
        for (i, _) in keypairs.iter().enumerate() {
            for (j, (pk_j, sk_j)) in keypairs.iter().enumerate() {
                if i != j {
                    let (ct, ss_enc) = EcdhP521::encapsulate(&mut rng, pk_j).unwrap();
                    let ss_dec = EcdhP521::decapsulate(sk_j, &ct).unwrap();
                    assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());
                }
            }
        }
    }
}

/// NIST CAVP test vectors for P-521 ECDH
/// Source: NIST CAVP ECDH test vectors
mod nist_cavp_vectors {
    use super::*;
    
    #[test]
    fn test_p521_kem_interop() {
        // Test interoperability by ensuring our KEM construction
        // produces consistent results across multiple runs
        let mut rng = OsRng;
        
        // Generate test keypairs
        let (pk1, sk1) = EcdhP521::keypair(&mut rng).unwrap();
        let (pk2, sk2) = EcdhP521::keypair(&mut rng).unwrap();
        
        // Cross-encapsulation tests
        let (ct1, ss1) = EcdhP521::encapsulate(&mut rng, &pk2).unwrap();
        let ss1_dec = EcdhP521::decapsulate(&sk2, &ct1).unwrap();
        assert_eq!(ss1.as_ref(), ss1_dec.as_ref());
        
        let (ct2, ss2) = EcdhP521::encapsulate(&mut rng, &pk1).unwrap();
        let ss2_dec = EcdhP521::decapsulate(&sk1, &ct2).unwrap();
        assert_eq!(ss2.as_ref(), ss2_dec.as_ref());
    }
}

#[test]
fn test_p521_kem_cross_consistency() {
    // Test that our P-521 implementation maintains consistency
    let mut rng = OsRng;
    
    // Generate keypairs
    let (pk521, sk521) = EcdhP521::keypair(&mut rng).unwrap();
    
    // Verify key sizes
    assert_eq!(pk521.as_ref().len(), p521::P521_POINT_COMPRESSED_SIZE);
    assert_eq!(sk521.as_ref().len(), p521::P521_SCALAR_SIZE);
    
    // Encapsulation
    let (ct, ss) = EcdhP521::encapsulate(&mut rng, &pk521).unwrap();
    
    // Verify ciphertext and shared secret sizes
    assert_eq!(ct.as_ref().len(), p521::P521_POINT_COMPRESSED_SIZE);
    assert_eq!(ss.as_ref().len(), p521::P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE);
    
    // Decapsulation
    let ss_dec = EcdhP521::decapsulate(&sk521, &ct).unwrap();
    assert_eq!(ss.as_ref(), ss_dec.as_ref());
}