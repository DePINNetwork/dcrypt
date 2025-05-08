// tests/constant_time_tests.rs

use tests::constant_time::config::TestConfig;
use tests::constant_time::tester::{TimingTester, generate_test_insights};
use dcrypt_primitives::block::aes::Aes128;
// Fix imports to use correct paths
use dcrypt_primitives::block::BlockCipher;
use dcrypt_primitives::aead::gcm::Gcm;
use dcrypt_core::traits::AuthenticatedCipher;
// Fix imports to use correct traits
use dcrypt_core::traits::symmetric::SymmetricCipher;
// Add SecretBytes import
use dcrypt_core::types::SecretBytes;
use dcrypt_primitives::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt_primitives::aead::chacha20poly1305::{CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_NONCE_SIZE};
use dcrypt_primitives::hash::{HashFunction, Sha256, Sha3_256};
use dcrypt_primitives::xof::{ExtendableOutputFunction, ShakeXof256, Blake3Xof};
use dcrypt_primitives::mac::hmac::Hmac;
use dcrypt_primitives::stream::chacha::chacha20::{ChaCha20, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE};
use dcrypt_primitives::kdf::hkdf::Hkdf;
use dcrypt_primitives::kdf::pbkdf2::Pbkdf2;
use dcrypt_primitives::kdf::KeyDerivationFunction;

#[test]
fn test_aes_constant_time() {
    let config = TestConfig::for_block_cipher();
    // Convert raw key bytes to SecretBytes
    let key_bytes = [0u8; 16];
    let key = SecretBytes::<16>::new(key_bytes);
    let cipher = Aes128::new(&key);

    let plain_zero = [0u8; 16];
    let plain_one  = [1u8; 16];

    // Warm-up phase
    for _ in 0..config.num_warmup {
        let mut b0 = plain_zero;
        let mut b1 = plain_one;
        cipher.encrypt_block(&mut b0).unwrap();
        cipher.encrypt_block(&mut b1).unwrap();
    }

    // Use configured sample/iteration counts
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    // Measure encrypting zero‐blocks
    let times0 = tester.measure(|| {
        let mut buf = plain_zero;
        cipher.encrypt_block(&mut buf).unwrap();
    });

    // Measure encrypting one‐blocks
    let times1 = tester.measure(|| {
        let mut buf = plain_one;
        cipher.encrypt_block(&mut buf).unwrap();
    });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &times0, 
        &times1,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("AES Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "AES");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "AES implementation is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

// Helper to set up the GCM instance once - updated to use SecretBytes
fn make_gcm() -> (Gcm<Aes128>, Vec<u8>, Vec<u8>) {
    // Convert raw key bytes to SecretBytes
    let key_bytes = [0u8; 16];
    let key = SecretBytes::<16>::new(key_bytes);
    let nonce = [0u8; 12];
    let aad = b"additional data";
    let plain = b"secret message";
    let cipher = Aes128::new(&key);
    let g = Gcm::new(cipher, &nonce).unwrap();
    let ct = g.internal_encrypt(plain, Some(aad)).unwrap(); // Use internal_encrypt method
    (g, ct, aad.to_vec())
}

#[test]
fn test_gcm_success_path_constant_time() {
    let config = TestConfig::for_aead();
    let (gcm, ciphertext, aad) = make_gcm();

    // More extensive warm-up - use internal_decrypt instead of decrypt
    for _ in 0..config.num_warmup {
        let _ = gcm.internal_decrypt(&ciphertext, Some(&aad));
    }

    // Use same configuration for both test runs
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    // Use internal_decrypt method
    let t1 = tester.measure(|| { let _ = gcm.internal_decrypt(&ciphertext, Some(&aad)); });
    let t2 = tester.measure(|| { let _ = gcm.internal_decrypt(&ciphertext, Some(&aad)); });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("GCM Success Path Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "GCM Success Path");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "GCM success path is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_gcm_error_path_constant_time() {
    let config = TestConfig::for_aead();
    let (gcm, mut ciphertext, aad) = make_gcm();
    // Flip a bit to force auth failure
    ciphertext[0] ^= 1;

    // Update to use internal_decrypt method
    for _ in 0..config.num_warmup {
        let _ = gcm.internal_decrypt(&ciphertext, Some(&aad));
    }

    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    // Update to use internal_decrypt method
    let t1 = tester.measure(|| { let _ = gcm.internal_decrypt(&ciphertext, Some(&aad)); });
    let t2 = tester.measure(|| { let _ = gcm.internal_decrypt(&ciphertext, Some(&aad)); });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("GCM Error Path Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "GCM Error Path");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "GCM error path is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

// Helper to set up the ChaCha20Poly1305 instance
fn make_chacha_poly() -> (ChaCha20Poly1305, Vec<u8>, Vec<u8>) {
    let key = [0x42; CHACHA20POLY1305_KEY_SIZE];
    let nonce = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let aad = b"additional authenticated data";
    let plaintext = b"confidential message";
    
    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();
    
    (cipher, ciphertext, aad.to_vec())
}

#[test]
fn test_chacha_poly_success_constant_time() {
    let config = TestConfig::for_chacha_poly();
    let (cipher, ciphertext, aad) = make_chacha_poly();
    let nonce = [0x24; CHACHA20POLY1305_NONCE_SIZE];

    for _ in 0..config.num_warmup {
        let _ = cipher.decrypt(&nonce, &ciphertext, Some(&aad));
    }

    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    let t1 = tester.measure(|| { 
        let _ = cipher.decrypt(&nonce, &ciphertext, Some(&aad)); 
    });
    let t2 = tester.measure(|| { 
        let _ = cipher.decrypt(&nonce, &ciphertext, Some(&aad)); 
    });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("ChaCha20Poly1305 Success Path Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "ChaCha20Poly1305 Success Path");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "ChaCha20Poly1305 success path is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_chacha_poly_failure_constant_time() {
    let config = TestConfig::for_chacha_poly();
    let (cipher, mut ciphertext, aad) = make_chacha_poly();
    let nonce = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    
    // Tamper with ciphertext to force authentication failure
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0x01;
    }

    for _ in 0..config.num_warmup {
        let _ = cipher.decrypt(&nonce, &ciphertext, Some(&aad));
    }

    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    let t1 = tester.measure(|| { 
        let _ = cipher.decrypt(&nonce, &ciphertext, Some(&aad)); 
    });
    let t2 = tester.measure(|| { 
        let _ = cipher.decrypt(&nonce, &ciphertext, Some(&aad)); 
    });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("ChaCha20Poly1305 Failure Path Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "ChaCha20Poly1305 Failure Path");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "ChaCha20Poly1305 failure path is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_sha256_constant_time() {
    let config = TestConfig::for_hash();
    let data_zeros = [0u8; 64];
    let data_ones = [1u8; 64];
    
    for _ in 0..config.num_warmup {
        let _ = Sha256::digest(&data_zeros);
        let _ = Sha256::digest(&data_ones);
    }
    
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    let t1 = tester.measure(|| { 
        let _ = Sha256::digest(&data_zeros); 
    });
    let t2 = tester.measure(|| { 
        let _ = Sha256::digest(&data_ones); 
    });
    
    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("SHA-256 Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "SHA-256");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "SHA-256 is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_sha3_256_constant_time() {
    let config = TestConfig::for_hash();
    let data_zeros = [0u8; 136]; // SHA3-256 rate block size
    let data_ones = [1u8; 136];
    
    for _ in 0..config.num_warmup {
        let _ = Sha3_256::digest(&data_zeros);
        let _ = Sha3_256::digest(&data_ones);
    }
    
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    let t1 = tester.measure(|| { 
        let _ = Sha3_256::digest(&data_zeros); 
    });
    let t2 = tester.measure(|| { 
        let _ = Sha3_256::digest(&data_ones); 
    });
    
    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("SHA3-256 Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "SHA3-256");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "SHA3-256 is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_shake256_constant_time() {
    let config = TestConfig::for_xof();
    let data_zeros = [0u8; 136]; // SHAKE-256 rate block size
    let data_ones = [1u8; 136];
    let output_len = 64;
    
    for _ in 0..config.num_warmup {
        let _ = ShakeXof256::generate(&data_zeros, output_len);
        let _ = ShakeXof256::generate(&data_ones, output_len);
    }
    
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    let t1 = tester.measure(|| { 
        let _ = ShakeXof256::generate(&data_zeros, output_len); 
    });
    let t2 = tester.measure(|| { 
        let _ = ShakeXof256::generate(&data_ones, output_len); 
    });
    
    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("SHAKE-256 Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "SHAKE-256");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "SHAKE-256 is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_blake3_xof_constant_time() {
    let config = TestConfig::for_blake3_xof();
    let data_zeros = [0u8; 64];
    let data_ones = [1u8; 64];
    let output_len = 64;

    let mut output = vec![0u8; output_len];
    let mut xof = Blake3Xof::new();

    // Warm-up phase
    for _ in 0..config.num_warmup {
        xof.update(&data_zeros).unwrap();
        xof.squeeze(&mut output).unwrap();
        xof.reset().unwrap();
        xof.update(&data_ones).unwrap();
        xof.squeeze(&mut output).unwrap();
        xof.reset().unwrap();
    }

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    // Measure timing for zeros
    let t1 = tester.measure(|| {
        xof.update(&data_zeros).unwrap();
        xof.squeeze(&mut output).unwrap();
        xof.reset().unwrap();
    });

    // Measure timing for ones
    let t2 = tester.measure(|| {
        xof.update(&data_ones).unwrap();
        xof.squeeze(&mut output).unwrap();
        xof.reset().unwrap();
    });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("BLAKE3-XOF Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "BLAKE3-XOF");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "BLAKE3-XOF is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_hmac_sha256_constant_time() {
    let config = TestConfig::for_mac();
    let key = [0x0bu8; 32];
    let data_zeros = [0u8; 64];
    let data_ones = [1u8; 64];

    // Warm-up
    for _ in 0..config.num_warmup {
        let _ = Hmac::<Sha256>::mac(&key, &data_zeros);
        let _ = Hmac::<Sha256>::mac(&key, &data_ones);
    }

    // Measurement
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    let t1 = tester.measure(|| {
        let _ = Hmac::<Sha256>::mac(&key, &data_zeros);
    });
    let t2 = tester.measure(|| {
        let _ = Hmac::<Sha256>::mac(&key, &data_ones);
    });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("HMAC-SHA256 Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Always generate insights for HMAC-SHA256 since it failed in the test run
    let insights = generate_test_insights(&analysis, &config, "HMAC-SHA256");
    println!("\n{}", insights);

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "HMAC-SHA256 is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_chacha20_constant_time() {
    let config = TestConfig::for_stream();
    let key = [0x42u8; CHACHA20_KEY_SIZE];
    let nonce = [0x24u8; CHACHA20_NONCE_SIZE];
    let data_zeros = [0u8; 64];
    let data_ones = [1u8; 64];
    
    for _ in 0..config.num_warmup {
        let mut chacha = ChaCha20::new(&key, &nonce);
        let mut buf = data_zeros.clone();
        chacha.encrypt(&mut buf);
        
        let mut chacha = ChaCha20::new(&key, &nonce);
        let mut buf = data_ones.clone();
        chacha.encrypt(&mut buf);
    }
    
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    let t1 = tester.measure(|| { 
        let mut chacha = ChaCha20::new(&key, &nonce);
        let mut buf = data_zeros.clone();
        chacha.encrypt(&mut buf);
    });
    let t2 = tester.measure(|| { 
        let mut chacha = ChaCha20::new(&key, &nonce);
        let mut buf = data_ones.clone();
        chacha.encrypt(&mut buf);
    });
    
    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("ChaCha20 Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "ChaCha20");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "ChaCha20 is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_hkdf_constant_time() {
    let config = TestConfig::for_hkdf();
    let secret1 = [0x0bu8; 32];
    let secret2 = [0x0cu8; 32];
    let salt = Some(&[0x0au8; 16][..]);
    let info = Some(&[0x01u8; 8][..]);
    let output_len = 32;
    
    for _ in 0..config.num_warmup {
        let hkdf = Hkdf::<Sha256>::new();
        let _ = hkdf.derive_key(&secret1, salt, info, output_len);
        let _ = hkdf.derive_key(&secret2, salt, info, output_len);
    }
    
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    let t1 = tester.measure(|| { 
        let hkdf = Hkdf::<Sha256>::new();
        let _ = hkdf.derive_key(&secret1, salt, info, output_len);
    });
    let t2 = tester.measure(|| { 
        let hkdf = Hkdf::<Sha256>::new();
        let _ = hkdf.derive_key(&secret2, salt, info, output_len);
    });
    
    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("HKDF Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "HKDF");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "HKDF is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_pbkdf2_constant_time() {
    let config = TestConfig::for_pbkdf2();
    let iterations = 50; // Test uses fewer iterations for performance
    let password1 = b"correct horse battery staple";
    let password2 = b"Tr0ub4dor&3";
    let salt = &[0x73, 0x61, 0x6c, 0x74]; // "salt" in ASCII
    let output_len = 32;

    // Warm-up phase
    for _ in 0..config.num_warmup {
        let _ = Pbkdf2::<Sha256>::pbkdf2(password1, salt, iterations, output_len);
        let _ = Pbkdf2::<Sha256>::pbkdf2(password2, salt, iterations, output_len);
    }

    // Timing measurements
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    let t1 = tester.measure(|| { 
        let _ = Pbkdf2::<Sha256>::pbkdf2(password1, salt, iterations, output_len);
    });
    let t2 = tester.measure(|| { 
        let _ = Pbkdf2::<Sha256>::pbkdf2(password2, salt, iterations, output_len);
    });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1, 
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("PBKDF2 Timing Analysis:");
    println!("  Mean times: {:.2} ns vs {:.2} ns", analysis.mean_a, analysis.mean_b);
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4} (calculated from t-distribution)", analysis.p_value);
    println!("  Effect size (Cohen's d): {:.3} - {}", 
            analysis.cohens_d, analysis.effect_size_interpretation);
    println!("  95% CI for mean difference: ({:.2}, {:.2}) ns", 
            analysis.confidence_interval.0, analysis.confidence_interval.1);
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!("  Relative std dev A: {:.3}", analysis.std_dev_a / analysis.mean_a);
    println!("  Relative std dev B: {:.3}", analysis.std_dev_b / analysis.mean_b);

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "PBKDF2");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "PBKDF2 is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}