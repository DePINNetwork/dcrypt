// tests/constant_time/aead_tests.rs
// Constant-time tests for AEAD ciphers (GCM and ChaCha20Poly1305)

use tests::suites::constant_time::config::TestConfig;
use tests::suites::constant_time::tester::{TimingTester, generate_test_insights};
use algorithms::block::aes::Aes128;
use algorithms::block::BlockCipher;
use algorithms::aead::gcm::Gcm;
use api::traits::AuthenticatedCipher;
use api::traits::symmetric::SymmetricCipher;
use api::types::SecretBytes;
use algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use algorithms::aead::chacha20poly1305::{CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_NONCE_SIZE};
use algorithms::types::Nonce;

// Helper to set up the GCM instance once - updated to use SecretBytes
fn make_gcm() -> (Gcm<Aes128>, Vec<u8>, Vec<u8>) {
    // Convert raw key bytes to SecretBytes
    let key_bytes = [0u8; 16];
    let key = SecretBytes::<16>::new(key_bytes);
    
    // Create a Nonce<12> from raw bytes
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::<12>::new(nonce_bytes);
    
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
    
    // Create a Nonce<12> from raw bytes
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);
    
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
    
    // Create a Nonce<12> from raw bytes
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);

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
    
    // Create a Nonce<12> from raw bytes
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);
    
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