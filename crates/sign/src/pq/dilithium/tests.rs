// File: crates/sign/src/pq/dilithium/tests.rs
//! Comprehensive test suite for Dilithium digital signature implementation

#[cfg(test)]
mod tests {
    use crate::pq::dilithium::*;
    use crate::pq::dilithium::arithmetic;
    use crate::pq::dilithium::polyvec;
    use crate::pq::dilithium::sampling;
    use crate::pq::dilithium::encoding;
    use api::Signature as SignatureTrait;
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;
    use params::pqc::dilithium::{Dilithium2Params, Dilithium3Params, Dilithium5Params};
    use params::pqc::dilithium::{DILITHIUM_N, DILITHIUM_Q};
    use crate::pq::dilithium::polyvec::{PolyVecK, PolyVecL};

    // Test vectors for basic operations
    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    const TEST_MESSAGE: &[u8] = b"Test message for Dilithium signature";

    /// Helper to create deterministic RNG for testing
    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(0xDEADBEEF)
    }

    // ========== Arithmetic Function Tests ==========

    #[test]
    fn test_power2round() {
        // Test cases from FIPS 203
        let test_cases = vec![
            (0, 13, (0, 0)),
            (4190208, 13, (-4096, 511)),
            (4194304, 13, (0, 512)),
            (8380416, 13, (-1, 1023)),
        ];

        for (r, d, expected) in test_cases {
            let (r0, r1) = arithmetic::power2round(r, d);
            assert_eq!((r0, r1), expected, "power2round({}, {}) failed", r, d);
            
            // Verify reconstruction
            let reconstructed = (r1 * (1 << d) + r0 as u32) % DILITHIUM_Q;
            assert_eq!(reconstructed, r, "Reconstruction failed for r={}", r);
        }
    }

    #[test]
    fn test_decompose() {
        // Test with alpha = 2*gamma2 for Dilithium2
        let gamma2 = (DILITHIUM_Q - 1) / 88;
        let alpha = 2 * gamma2;
        
        let test_cases = vec![
            (0, alpha, (0, 0)),
            (gamma2, alpha, (gamma2 as i32, 0)),
            (alpha, alpha, (-(gamma2 as i32), 1)),
            (DILITHIUM_Q - 1, alpha, (-1, 44)),
        ];

        for (r, alpha_val, expected) in test_cases {
            let (r0, r1) = arithmetic::decompose(r, alpha_val);
            assert_eq!((r0, r1), expected, "decompose({}, {}) failed", r, alpha_val);
            
            // Verify reconstruction
            let reconstructed = ((r1 * alpha_val) as i32 + r0 + DILITHIUM_Q as i32) as u32 % DILITHIUM_Q;
            assert_eq!(reconstructed, r, "Reconstruction failed for r={}", r);
        }
    }

    #[test]
    fn test_make_use_hint() {
        let gamma2 = (DILITHIUM_Q - 1) / 88;
        
        // Test MakeHint
        assert_eq!(arithmetic::make_hint_coeff(0, 0, gamma2), false);
        assert_eq!(arithmetic::make_hint_coeff(1, 0, gamma2), true);
        assert_eq!(arithmetic::make_hint_coeff(gamma2 as i32, 0, gamma2), false);
        assert_eq!(arithmetic::make_hint_coeff(-(gamma2 as i32), 0, gamma2), false);
        
        // Test UseHint
        let test_r = 1000000;
        let (r0, r1) = arithmetic::decompose(test_r, 2 * gamma2);
        
        // No hint
        assert_eq!(arithmetic::use_hint_coeff(false, test_r, gamma2), r1);
        
        // With hint
        if r0 > 0 {
            assert_eq!(arithmetic::use_hint_coeff(true, test_r, gamma2), r1 + 1);
        } else if r0 < 0 {
            assert_eq!(arithmetic::use_hint_coeff(true, test_r, gamma2), r1 - 1);
        }
    }

    // ========== Sampling Function Tests ==========

    #[test]
    fn test_sample_cbd_distribution() {
        use sampling::sample_poly_cbd_eta;
        
        // Test CBD sampling for different eta values
        for eta in [2u32, 4u32] {
            let poly = sample_poly_cbd_eta::<Dilithium2Params>(&TEST_SEED, 0, eta).unwrap();
            
            // Check all coefficients are valid
            for &coeff in poly.coeffs.iter() {
                assert!(coeff < DILITHIUM_Q);
            }
            
            // Check coefficient distribution (centered around 0)
            let mut sum = 0i64;
            for &coeff in poly.coeffs.iter() {
                let centered = if coeff > DILITHIUM_Q / 2 {
                    coeff as i64 - DILITHIUM_Q as i64
                } else {
                    coeff as i64
                };
                sum += centered.abs();
            }
            
            // Average absolute value should be close to eta/2
            let avg = sum / DILITHIUM_N as i64;
            assert!(avg <= eta as i64, "CBD distribution check failed for eta={}", eta);
        }
    }

    #[test]
    fn test_sample_uniform_gamma1() {
        use sampling::sample_polyvecl_uniform_gamma1;
        
        // Test for Dilithium2 (gamma1 = 2^17)
        let gamma1 = 1 << 17;
        let polyvec = sample_polyvecl_uniform_gamma1::<Dilithium2Params>(
            &TEST_SEED, 0, gamma1
        ).unwrap();
        
        // Check all coefficients are in correct range
        for poly in polyvec.polys.iter() {
            for &coeff in poly.coeffs.iter() {
                assert!(coeff < DILITHIUM_Q);
                
                // Check centered value is in [-gamma1+1, gamma1-1]
                let centered = if coeff > DILITHIUM_Q / 2 {
                    coeff as i32 - DILITHIUM_Q as i32
                } else {
                    coeff as i32
                };
                assert!(centered >= -(gamma1 as i32 - 1));
                assert!(centered <= gamma1 as i32 - 1);
            }
        }
    }

    #[test]
    fn test_sample_challenge() {
        use sampling::sample_challenge_c;
        
        let tau = 39; // Dilithium2 tau
        let c = sample_challenge_c::<Dilithium2Params>(&TEST_SEED, tau).unwrap();
        
        // Count non-zero coefficients
        let mut nonzero_count = 0;
        let mut pos_count = 0;
        let mut neg_count = 0;
        
        for &coeff in c.coeffs.iter() {
            if coeff == 1 {
                nonzero_count += 1;
                pos_count += 1;
            } else if coeff == DILITHIUM_Q - 1 {
                nonzero_count += 1;
                neg_count += 1;
            } else {
                assert_eq!(coeff, 0);
            }
        }
        
        assert_eq!(nonzero_count, tau, "Wrong number of non-zero coefficients");
        assert!(pos_count > 0 && neg_count > 0, "Should have both signs");
    }

    // ========== Encoding Function Tests ==========

    #[test]
    fn test_public_key_pack_unpack() {
        use encoding::{pack_public_key, unpack_public_key};
        
        let mut rng = test_rng();
        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut rho);
        
        // Create random t1 vector
        let mut t1_vec = PolyVecK::<Dilithium2Params>::zero();
        for poly in t1_vec.polys.iter_mut() {
            for coeff in poly.coeffs.iter_mut() {
                *coeff = rng.next_u32() % 1024; // t1 coefficients are 10 bits
            }
        }
        
        // Pack and unpack
        let packed = pack_public_key::<Dilithium2Params>(&rho, &t1_vec).unwrap();
        assert_eq!(packed.len(), Dilithium2Params::PUBLIC_KEY_BYTES);
        
        let (rho_unpacked, t1_unpacked) = unpack_public_key::<Dilithium2Params>(&packed).unwrap();
        
        assert_eq!(rho, rho_unpacked);
        for i in 0..Dilithium2Params::K_DIM {
            assert_eq!(t1_vec.polys[i].coeffs, t1_unpacked.polys[i].coeffs);
        }
    }

    #[test]
    fn test_signature_pack_unpack() {
        use encoding::{pack_signature, unpack_signature};
        use sampling::sample_polyvecl_uniform_gamma1;
        
        let gamma1 = 1 << 17;
        
        // Create test signature components
        let c_tilde = TEST_SEED;
        let z_vec = sample_polyvecl_uniform_gamma1::<Dilithium2Params>(
            &TEST_SEED, 0, gamma1
        ).unwrap();
        
        // Create hint vector with some set bits
        let mut h_hint = PolyVecK::<Dilithium2Params>::zero();
        h_hint.polys[0].coeffs[0] = 1;
        h_hint.polys[1].coeffs[10] = 1;
        h_hint.polys[2].coeffs[100] = 1;
        
        // Pack and unpack
        let packed = pack_signature::<Dilithium2Params>(&c_tilde, &z_vec, &h_hint).unwrap();
        assert_eq!(packed.len(), Dilithium2Params::SIGNATURE_SIZE);
        
        let (c_tilde_unpacked, z_unpacked, _h_unpacked) = // FIXED: Added underscore
            unpack_signature::<Dilithium2Params>(&packed).unwrap();
        
        assert_eq!(c_tilde, c_tilde_unpacked);
        
        // Check z coefficients (allowing for modular reduction)
        for i in 0..Dilithium2Params::L_DIM {
            for j in 0..DILITHIUM_N {
                let orig = z_vec.polys[i].coeffs[j] % DILITHIUM_Q;
                let unpacked = z_unpacked.polys[i].coeffs[j] % DILITHIUM_Q;
                assert_eq!(orig, unpacked, "z coefficient mismatch at [{},{}]", i, j);
            }
        }
    }

    // ========== PolyVec Operation Tests ==========

    #[test]
    fn test_polyvec_operations() {
        let mut pv1 = PolyVecL::<Dilithium2Params>::zero();
        let mut pv2 = PolyVecL::<Dilithium2Params>::zero();
        
        // Set some test values
        for i in 0..Dilithium2Params::L_DIM {
            for j in 0..10 {
                pv1.polys[i].coeffs[j] = (i * 10 + j) as u32;
                pv2.polys[i].coeffs[j] = ((i + 1) * (j + 1)) as u32;
            }
        }
        
        // Test addition
        let sum = pv1.add(&pv2);
        for i in 0..Dilithium2Params::L_DIM {
            for j in 0..10 {
                assert_eq!(
                    sum.polys[i].coeffs[j],
                    pv1.polys[i].coeffs[j] + pv2.polys[i].coeffs[j]
                );
            }
        }
        
        // Test subtraction
        let diff = pv1.sub(&pv2);
        for i in 0..Dilithium2Params::L_DIM {
            for j in 0..10 {
                let expected = (pv1.polys[i].coeffs[j] as i32 - pv2.polys[i].coeffs[j] as i32 
                    + DILITHIUM_Q as i32) as u32 % DILITHIUM_Q;
                assert_eq!(diff.polys[i].coeffs[j], expected);
            }
        }
    }

    #[test]
    fn test_matrix_expansion() {
        use polyvec::expand_matrix_a;
        
        let matrix = expand_matrix_a::<Dilithium2Params>(&TEST_SEED).unwrap();
        
        // Check dimensions
        assert_eq!(matrix.len(), Dilithium2Params::K_DIM);
        for row in matrix.iter() {
            assert_eq!(row.polys.len(), Dilithium2Params::L_DIM);
        }
        
        // Check all coefficients are valid
        for row in matrix.iter() {
            for poly in row.polys.iter() {
                for &coeff in poly.coeffs.iter() {
                    assert!(coeff < DILITHIUM_Q);
                }
            }
        }
        
        // Check determinism
        let matrix2 = expand_matrix_a::<Dilithium2Params>(&TEST_SEED).unwrap();
        for i in 0..Dilithium2Params::K_DIM {
            for j in 0..Dilithium2Params::L_DIM {
                assert_eq!(matrix[i].polys[j].coeffs, matrix2[i].polys[j].coeffs);
            }
        }
    }

    // ========== Integration Tests ==========

    #[test]
    fn test_dilithium2_sign_verify() {
        let mut rng = test_rng();
        
        // Generate keypair
        let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();
        
        // Sign message
        let sig = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();
        
        // Verify signature
        assert!(Dilithium2::verify(TEST_MESSAGE, &sig, &pk).is_ok());
        
        // Verify with wrong message fails
        let wrong_msg = b"Wrong message";
        assert!(Dilithium2::verify(wrong_msg, &sig, &pk).is_err());
        
        // Verify with corrupted signature fails
        let mut bad_sig = sig.clone();
        bad_sig.0[10] ^= 0xFF;
        assert!(Dilithium2::verify(TEST_MESSAGE, &bad_sig, &pk).is_err());
    }

    #[test]
    fn test_dilithium3_sign_verify() {
        let mut rng = test_rng();
        
        let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();
        let sig = Dilithium3::sign(TEST_MESSAGE, &sk).unwrap();
        assert!(Dilithium3::verify(TEST_MESSAGE, &sig, &pk).is_ok());
    }

    #[test]
    fn test_dilithium5_sign_verify() {
        let mut rng = test_rng();
        
        let (pk, sk) = Dilithium5::keypair(&mut rng).unwrap();
        let sig = Dilithium5::sign(TEST_MESSAGE, &sk).unwrap();
        assert!(Dilithium5::verify(TEST_MESSAGE, &sig, &pk).is_ok());
    }

    #[test]
    fn test_empty_message() {
        let mut rng = test_rng();
        let empty_msg = b"";
        
        let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();
        let sig = Dilithium2::sign(empty_msg, &sk).unwrap();
        assert!(Dilithium2::verify(empty_msg, &sig, &pk).is_ok());
    }

    #[test]
    fn test_large_message() {
        let mut rng = test_rng();
        let large_msg = vec![0xAB; 10000]; // 10KB message
        
        let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();
        let sig = Dilithium2::sign(&large_msg, &sk).unwrap();
        assert!(Dilithium2::verify(&large_msg, &sig, &pk).is_ok());
    }

    #[test]
    fn test_deterministic_signatures() {
        let mut rng = test_rng();
        
        let (_pk, sk) = Dilithium2::keypair(&mut rng).unwrap(); // FIXED: Added underscore
        
        // Sign same message twice
        let sig1 = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();
        let sig2 = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();
        
        // Signatures should be identical (Dilithium is deterministic)
        assert_eq!(sig1.0, sig2.0);
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(Dilithium2Params::PUBLIC_KEY_BYTES, 1312);
        assert_eq!(Dilithium2Params::SECRET_KEY_BYTES, 2528);
        assert_eq!(Dilithium2Params::SIGNATURE_SIZE, 2420);
        
        assert_eq!(Dilithium3Params::PUBLIC_KEY_BYTES, 1952);
        assert_eq!(Dilithium3Params::SECRET_KEY_BYTES, 4000);
        assert_eq!(Dilithium3Params::SIGNATURE_SIZE, 3293);
        
        assert_eq!(Dilithium5Params::PUBLIC_KEY_BYTES, 2592);
        assert_eq!(Dilithium5Params::SECRET_KEY_BYTES, 4864);
        assert_eq!(Dilithium5Params::SIGNATURE_SIZE, 4595);
    }

    // ========== Property-Based Tests ==========

    #[test]
    fn test_norm_bounds() {
        use arithmetic::check_norm_poly;
        use sampling::sample_poly_cbd_eta;
        
        // Test that CBD samples respect norm bounds
        for eta in [2u32, 4u32] {
            let poly = sample_poly_cbd_eta::<Dilithium2Params>(&TEST_SEED, 0, eta).unwrap();
            assert!(check_norm_poly::<Dilithium2Params>(&poly, eta));
        }
    }

    #[test]
    fn test_ntt_consistency() {
        use polyvec::expand_matrix_a;
        
        let matrix = expand_matrix_a::<Dilithium2Params>(&TEST_SEED).unwrap();
        
        // Convert to NTT and back
        let mut matrix_ntt = matrix.clone();
        for row in matrix_ntt.iter_mut() {
            row.ntt_inplace().unwrap();
            row.inv_ntt_inplace().unwrap();
        }
        
        // Should recover original
        for i in 0..Dilithium2Params::K_DIM {
            for j in 0..Dilithium2Params::L_DIM {
                for k in 0..DILITHIUM_N {
                    let orig = matrix[i].polys[j].coeffs[k];
                    let recovered = matrix_ntt[i].polys[j].coeffs[k];
                    assert_eq!(orig, recovered, "NTT round-trip failed at [{},{},{}]", i, j, k);
                }
            }
        }
    }

    // ========== Error Case Tests ==========

    #[test]
    fn test_invalid_public_key_size() {
        use encoding::unpack_public_key;
        
        let short_pk = vec![0u8; 100]; // Too short
        assert!(unpack_public_key::<Dilithium2Params>(&short_pk).is_err());
        
        let long_pk = vec![0u8; 10000]; // Too long
        assert!(unpack_public_key::<Dilithium2Params>(&long_pk).is_err());
    }

    #[test]
    fn test_invalid_signature_size() {
        use encoding::unpack_signature;
        
        let short_sig = vec![0u8; 100];
        assert!(unpack_signature::<Dilithium2Params>(&short_sig).is_err());
    }

    #[test]
    fn test_invalid_secret_key() {
        let bad_sk = DilithiumSecretKey(vec![0u8; 100]); // Wrong size
        assert!(Dilithium2::sign(TEST_MESSAGE, &bad_sk).is_err());
    }

    // ========== Benchmark Helpers (not actual benchmarks) ==========

    #[test]
    #[ignore] // Run with --ignored to see timing
    fn timing_keypair_generation() {
        use std::time::Instant;
        
        let mut rng = test_rng();
        let iterations = 10;
        
        for &(name, level) in &[("Dilithium2", 2), ("Dilithium3", 3), ("Dilithium5", 5)] {
            let start = Instant::now();
            
            for _ in 0..iterations {
                match level {
                    2 => { let _ = Dilithium2::keypair(&mut rng).unwrap(); }
                    3 => { let _ = Dilithium3::keypair(&mut rng).unwrap(); }
                    5 => { let _ = Dilithium5::keypair(&mut rng).unwrap(); }
                    _ => unreachable!()
                }
            }
            
            let elapsed = start.elapsed();
            println!("{} keypair generation: {:?} per operation", 
                name, elapsed / iterations);
        }
    }

    #[test]
    #[ignore] // Run with --ignored to see timing
    fn timing_sign_verify() {
        use std::time::Instant;
        
        let mut rng = test_rng();
        let iterations = 10;
        
        // Pre-generate keypairs
        let (pk2, sk2) = Dilithium2::keypair(&mut rng).unwrap();
        let (pk3, sk3) = Dilithium3::keypair(&mut rng).unwrap();
        let (pk5, sk5) = Dilithium5::keypair(&mut rng).unwrap();
        
        // Time signing
        println!("\nSigning times:");
        for &(name, level) in &[("Dilithium2", 2), ("Dilithium3", 3), ("Dilithium5", 5)] {
            let start = Instant::now();
            
            for _ in 0..iterations {
                match level {
                    2 => { let _ = Dilithium2::sign(TEST_MESSAGE, &sk2).unwrap(); }
                    3 => { let _ = Dilithium3::sign(TEST_MESSAGE, &sk3).unwrap(); }
                    5 => { let _ = Dilithium5::sign(TEST_MESSAGE, &sk5).unwrap(); }
                    _ => unreachable!()
                }
            }
            
            let elapsed = start.elapsed();
            println!("{}: {:?} per operation", name, elapsed / iterations);
        }
        
        // Pre-generate signatures
        let sig2 = Dilithium2::sign(TEST_MESSAGE, &sk2).unwrap();
        let sig3 = Dilithium3::sign(TEST_MESSAGE, &sk3).unwrap();
        let sig5 = Dilithium5::sign(TEST_MESSAGE, &sk5).unwrap();
        
        // Time verification
        println!("\nVerification times:");
        for &(name, level) in &[("Dilithium2", 2), ("Dilithium3", 3), ("Dilithium5", 5)] {
            let start = Instant::now();
            
            for _ in 0..iterations {
                match level {
                    2 => { let _ = Dilithium2::verify(TEST_MESSAGE, &sig2, &pk2).unwrap(); }
                    3 => { let _ = Dilithium3::verify(TEST_MESSAGE, &sig3, &pk3).unwrap(); }
                    5 => { let _ = Dilithium5::verify(TEST_MESSAGE, &sig5, &pk5).unwrap(); }
                    _ => unreachable!()
                }
            }
            
            let elapsed = start.elapsed();
            println!("{}: {:?} per operation", name, elapsed / iterations);
        }
    }
}