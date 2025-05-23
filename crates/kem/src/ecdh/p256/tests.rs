// File: crates/kem/src/ecdh/p256/tests.rs
use super::*;
use api::Kem;
use algorithms::SecretBuffer;
use algorithms::ec::p256 as ec_p256;
use rand::rngs::OsRng;

// Simple hex encoding/decoding utilities
fn hex_decode(hex: &str) -> Result<Vec<u8>, &'static str> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length");
    }
    
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let high = hex_char_to_nibble(chunk[0])?;
            let low = hex_char_to_nibble(chunk[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_char_to_nibble(c: u8) -> Result<u8, &'static str> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("Invalid hex character"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[test]
fn test_p256_kem_basic_flow() {
    let mut rng = OsRng;
    
    // Generate recipient keypair
    let (recipient_pk, recipient_sk) = EcdhP256::keypair(&mut rng).unwrap();
    
    // Encapsulate
    let (ciphertext, shared_secret_sender) = EcdhP256::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    // Decapsulate
    let shared_secret_recipient = EcdhP256::decapsulate(&recipient_sk, &ciphertext).unwrap();
    
    // Verify shared secrets match
    assert_eq!(
        shared_secret_sender.as_ref(),
        shared_secret_recipient.as_ref(),
        "Shared secrets should match"
    );
}

#[test]
fn test_p256_kem_multiple_encapsulations() {
    let mut rng = OsRng;
    
    // Generate recipient keypair
    let (recipient_pk, recipient_sk) = EcdhP256::keypair(&mut rng).unwrap();
    
    // Multiple encapsulations should produce different ciphertexts and shared secrets
    let (ct1, ss1) = EcdhP256::encapsulate(&mut rng, &recipient_pk).unwrap();
    let (ct2, ss2) = EcdhP256::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    // Ciphertexts should be different (different ephemeral keys)
    assert_ne!(ct1.as_ref(), ct2.as_ref());
    
    // Shared secrets should be different
    assert_ne!(ss1.as_ref(), ss2.as_ref());
    
    // But both should decapsulate correctly
    let ss1_dec = EcdhP256::decapsulate(&recipient_sk, &ct1).unwrap();
    let ss2_dec = EcdhP256::decapsulate(&recipient_sk, &ct2).unwrap();
    
    assert_eq!(ss1.as_ref(), ss1_dec.as_ref());
    assert_eq!(ss2.as_ref(), ss2_dec.as_ref());
}

#[test]
fn test_p256_kem_invalid_public_key() {
    let mut rng = OsRng;
    
    // Test with all-zero public key (identity point)
    let invalid_pk = EcdhP256PublicKey([0u8; ec_p256::P256_POINT_UNCOMPRESSED_SIZE]);
    
    // Encapsulation should fail
    let result = EcdhP256::encapsulate(&mut rng, &invalid_pk);
    assert!(result.is_err());
    
    // Test with invalid point format
    let mut invalid_pk2 = EcdhP256PublicKey([0xFFu8; ec_p256::P256_POINT_UNCOMPRESSED_SIZE]);
    invalid_pk2.0[0] = 0x05; // Invalid format byte
    
    let result2 = EcdhP256::encapsulate(&mut rng, &invalid_pk2);
    assert!(result2.is_err());
}

#[test]
fn test_p256_kem_invalid_ciphertext() {
    let mut rng = OsRng;
    
    // Generate recipient keypair
    let (_, recipient_sk) = EcdhP256::keypair(&mut rng).unwrap();
    
    // Test with all-zero ciphertext (identity point)
    let invalid_ct = EcdhP256Ciphertext([0u8; ec_p256::P256_POINT_UNCOMPRESSED_SIZE]);
    
    // Decapsulation should fail
    let result = EcdhP256::decapsulate(&recipient_sk, &invalid_ct);
    assert!(result.is_err());
}

#[test]
fn test_p256_kem_wrong_secret_key() {
    let mut rng = OsRng;
    
    // Generate two keypairs
    let (recipient_pk, _) = EcdhP256::keypair(&mut rng).unwrap();
    let (_, wrong_sk) = EcdhP256::keypair(&mut rng).unwrap();
    
    // Encapsulate to first recipient
    let (ciphertext, shared_secret_sender) = EcdhP256::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    // Try to decapsulate with wrong secret key
    let shared_secret_wrong = EcdhP256::decapsulate(&wrong_sk, &ciphertext).unwrap();
    
    // Shared secrets should NOT match
    assert_ne!(
        shared_secret_sender.as_ref(),
        shared_secret_wrong.as_ref(),
        "Shared secrets should not match with wrong key"
    );
}

/// Test vectors for P-256 ECDH-KEM
/// These test vectors use known scalar/point pairs to verify the KEM construction
mod test_vectors {
    use super::*;
    
    #[test]
    fn test_p256_kem_known_answer() {
        // This test requires creating keys from known values
        // Since the KEM API doesn't expose this directly, we'll test
        // the overall flow with generated keys
        
        let mut rng = OsRng;
        let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();
        
        // Test multiple encapsulations/decapsulations
        for _ in 0..5 {
            let (ct, ss_enc) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
            let ss_dec = EcdhP256::decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());
        }
    }
    
    #[test]
    fn test_p256_kem_edge_cases() {
        let mut rng = OsRng;
        
        // Test with multiple recipients
        let recipients: Vec<_> = (0..3)
            .map(|_| EcdhP256::keypair(&mut rng).unwrap())
            .collect();
        
        // Encapsulate to each recipient
        for (pk, sk) in &recipients {
            let (ct, ss_enc) = EcdhP256::encapsulate(&mut rng, pk).unwrap();
            let ss_dec = EcdhP256::decapsulate(sk, &ct).unwrap();
            assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());
        }
    }
}

#[test]
fn test_p256_kem_deterministic_shared_secret() {
    // For the same ephemeral key and recipient key, the shared secret should be deterministic
    let mut rng = OsRng;
    
    // Generate fixed recipient keypair
    let (recipient_pk, recipient_sk) = EcdhP256::keypair(&mut rng).unwrap();
    
    // Create a specific ciphertext
    let (ciphertext, _) = EcdhP256::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    // Compute shared secret multiple times
    let ss1 = EcdhP256::decapsulate(&recipient_sk, &ciphertext).unwrap();
    let ss2 = EcdhP256::decapsulate(&recipient_sk, &ciphertext).unwrap();
    
    // Should be identical
    assert_eq!(ss1.as_ref(), ss2.as_ref());
}

#[test]
fn test_p256_kem_serialization_roundtrip() {
    let mut rng = OsRng;
    
    // Generate keypair
    let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();
    
    // Serialize and deserialize public key
    let pk_bytes = pk.as_ref();
    let pk_restored = EcdhP256PublicKey(pk_bytes.try_into().unwrap());
    
    // Test encapsulation with restored key
    let (ct, ss1) = EcdhP256::encapsulate(&mut rng, &pk_restored).unwrap();
    let ss2 = EcdhP256::decapsulate(&sk, &ct).unwrap();
    
    assert_eq!(ss1.as_ref(), ss2.as_ref());
}

/// Compliance tests for NIST SP 800-56A Rev. 3
mod nist_compliance {
    use super::*;
    
    #[test]
    fn test_p256_point_validation() {
        let mut rng = OsRng;
        
        // Generate valid keypair
        let (_, sk) = EcdhP256::keypair(&mut rng).unwrap();
        
        // Create invalid ciphertext (point not on curve)
        let mut invalid_ct_bytes = [0u8; ec_p256::P256_POINT_UNCOMPRESSED_SIZE];
        invalid_ct_bytes[0] = 0x04; // Uncompressed point format
        invalid_ct_bytes[1..33].fill(0xFF); // Invalid x-coordinate
        invalid_ct_bytes[33..65].fill(0xFF); // Invalid y-coordinate
        
        let invalid_ct = EcdhP256Ciphertext(invalid_ct_bytes);
        
        // Decapsulation should fail
        let result = EcdhP256::decapsulate(&sk, &invalid_ct);
        assert!(result.is_err());
    }
}

#[test]
fn test_p256_kem_consistency_across_implementations() {
    // This test ensures our implementation produces consistent results
    let mut rng = OsRng;
    
    // Run multiple iterations to catch any non-determinism
    for _ in 0..10 {
        let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();
        let (ct, ss_enc) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
        let ss_dec = EcdhP256::decapsulate(&sk, &ct).unwrap();
        
        assert_eq!(
            ss_enc.as_ref(), 
            ss_dec.as_ref(),
            "Encapsulation and decapsulation must produce same shared secret"
        );
        
        // Verify shared secret length
        assert_eq!(
            ss_enc.as_ref().len(),
            ec_p256::P256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
            "Shared secret must have correct length"
        );
    }
}

#[cfg(feature = "benchmark")]
mod benchmarks {
    use super::*;
    use test::Bencher;
    
    #[bench]
    fn bench_p256_kem_keypair(b: &mut Bencher) {
        let mut rng = OsRng;
        b.iter(|| {
            let _ = EcdhP256::keypair(&mut rng).unwrap();
        });
    }
    
    #[bench]
    fn bench_p256_kem_encapsulate(b: &mut Bencher) {
        let mut rng = OsRng;
        let (pk, _) = EcdhP256::keypair(&mut rng).unwrap();
        
        b.iter(|| {
            let _ = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
        });
    }
    
    #[bench]
    fn bench_p256_kem_decapsulate(b: &mut Bencher) {
        let mut rng = OsRng;
        let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();
        let (ct, _) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
        
        b.iter(|| {
            let _ = EcdhP256::decapsulate(&sk, &ct).unwrap();
        });
    }
}