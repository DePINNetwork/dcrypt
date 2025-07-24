// tests/constant_time/kdf/argon2/mod.rs
// Constant-time tests for Argon2 password hashing

use tests::suites::constant_time::config::TestConfig;
use tests::suites::constant_time::tester::{TimingTester, generate_test_insights};
use dcrypt_algorithms::kdf::argon2::{Argon2, Algorithm, Params};
use dcrypt_algorithms::kdf::PasswordHashFunction; // Added missing trait import
use dcrypt_algorithms::types::Salt;
use dcrypt_api::types::SecretBytes;
// We need to keep the import but it's likely available through another module
use dcrypt_algorithms::kdf; // This should provide access to Zeroizing through re-export

// Helper function instead of impl
fn create_argon2_config() -> TestConfig {
    TestConfig {
        num_warmup: 5,
        num_samples: 30,
        num_iterations: 3,
        mean_ratio_max: 1.2,
        mean_ratio_min: 0.8,         // Added missing field
        t_stat_threshold: 2.0,
        std_dev_threshold: 0.15,     // Added missing field
        combined_score_threshold: 1.5,
    }
}

#[test]
fn test_argon2id_verify_constant_time() {
    // Configure Argon2 with minimal settings for faster testing
    const SALT_LEN: usize = 16;
    
    // Create password bytes
    let mut correct_pw_bytes = [0u8; 32];
    let src_pw = b"correct_password";
    correct_pw_bytes[..src_pw.len()].copy_from_slice(src_pw);
    let correct_password = SecretBytes::<32>::new(correct_pw_bytes);
    
    let mut wrong_pw_bytes = [0u8; 32];
    let src_wrong_pw = b"wrong_password";
    wrong_pw_bytes[..src_wrong_pw.len()].copy_from_slice(src_wrong_pw);
    let wrong_password = SecretBytes::<32>::new(wrong_pw_bytes);
    
    // Generate a salt
    let salt_data = [0x42; SALT_LEN];
    let salt = Salt::<SALT_LEN>::new(salt_data);
    
    // Create minimal Argon2 params for test - use small values to keep test fast
    let params = Params {
        argon_type: Algorithm::Argon2id,
        version: 0x13, // v1.3
        memory_cost: 8 * 4, // Minimum for 4 lanes
        time_cost: 1,
        parallelism: 4,
        output_len: 32,
        salt: salt.clone(), // Clone the salt to avoid ownership issues
        ad: None,
        secret: None,
    };
    
    let argon2 = Argon2::new_with_params(params);
    
    // Hash the correct password to get a reference hash
    let hash_result = argon2.hash_password(correct_password.as_ref()).expect("Hashing failed");
    
    // Create a PasswordHash struct using the actual implementation's method
    let stored_hash = dcrypt_algorithms::kdf::PasswordHash {
        algorithm: "argon2id".to_string(),
        params: [
            ("v".to_string(), "19".to_string()),
            ("m".to_string(), "32".to_string()),
            ("t".to_string(), "1".to_string()),
            ("p".to_string(), "4".to_string()),
        ].iter().cloned().collect(),
        salt: salt.as_ref().to_vec().into(), // Use .into() to convert Vec<u8> to Zeroizing<Vec<u8>>
        hash: hash_result,
    };
    
    let config = create_argon2_config(); // Using helper function
    
    // Warm-up phase
    for _ in 0..config.num_warmup {
        let _ = argon2.verify(&correct_password, &stored_hash);
        let _ = argon2.verify(&wrong_password, &stored_hash);
    }
    
    // Measurement phase
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    // Measure verify time for correct password
    let t1 = tester.measure(|| {
        let _ = argon2.verify(&correct_password, &stored_hash);
    });
    
    // Measure verify time for wrong password
    let t2 = tester.measure(|| {
        let _ = argon2.verify(&wrong_password, &stored_hash);
    });
    
    // Analyze if verification is constant-time
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
    
    // Output detailed diagnostics
    println!("Argon2id Verify Timing Analysis:");
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
        let insights = generate_test_insights(&analysis, &config, "Argon2id Verify");
        println!("\n{}", insights);
    }
    
    // Assert that verification is constant-time
    assert!(
        analysis.is_constant_time,
        "Argon2id verify is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_argon2_constant_time_compare() {
    const SALT_LEN: usize = 16;
    let salt_data = [0x42; SALT_LEN];
    let salt = Salt::<SALT_LEN>::new(salt_data);
    
    // Create minimal Argon2 params
    let params = Params {
        argon_type: Algorithm::Argon2id,
        version: 0x13, // v1.3
        memory_cost: 8 * 4, // Minimum for 4 lanes
        time_cost: 1,
        parallelism: 4,
        output_len: 32,
        salt: salt.clone(), // Already correctly cloned here
        ad: None,
        secret: None,
    };
    
    // Create password bytes
    let mut pw_bytes = [0u8; 32];
    let src_pw = b"test_password";
    pw_bytes[..src_pw.len()].copy_from_slice(src_pw);
    let password = SecretBytes::<32>::new(pw_bytes);
    
    // Generate two different hash outputs
    let argon2 = Argon2::new_with_params(params.clone());
    let hash1 = argon2.hash_password(password.as_ref()).expect("Hashing failed");
    
    // Create a slightly different hash for comparison
    let mut hash2 = hash1.clone();
    if !hash2.is_empty() {
        hash2[0] ^= 0x01; // Flip a bit in the first byte
    }
    
    let config = create_argon2_config(); // Using helper function
    
    // Warm-up
    for _ in 0..config.num_warmup {
        let _ = dcrypt_algorithms::kdf::common::constant_time_eq(&hash1, &hash2);
    }
    
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    
    // Measure comparison timing for hashes differing in the first byte
    let t1 = tester.measure(|| {
        dcrypt_algorithms::kdf::common::constant_time_eq(&hash1, &hash2); // Added semicolon
    });
    
    // Create hash3 that matches hash1 except for the last byte
    let mut hash3 = hash1.clone();
    if !hash3.is_empty() {
        // Fix borrowing issue by storing the index first
        let last_index = hash3.len() - 1;
        hash3[last_index] ^= 0x01; // Flip a bit in the last byte
    }
    
    // Measure comparison timing for hashes differing in the last byte
    let t2 = tester.measure(|| {
        dcrypt_algorithms::kdf::common::constant_time_eq(&hash1, &hash3); // Added semicolon
    });
    
    // Analyze if comparison is constant-time
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
    
    // Output detailed diagnostics
    println!("Argon2 Hash Comparison Timing Analysis:");
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
        let insights = generate_test_insights(&analysis, &config, "Argon2 Hash Comparison");
        println!("\n{}", insights);
    }
    
    // Assert that hash comparison is constant-time
    assert!(
        analysis.is_constant_time,
        "Argon2 hash comparison is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

// NOTE: The index_alpha function is private in the algorithm implementation
// This test has been commented out until the function is made public or the test approach is updated
/*
#[test]
fn test_index_alpha_constant_time() {
    // Test removed or commented out due to private function
}
*/