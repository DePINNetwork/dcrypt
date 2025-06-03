// tests/constant_time/kdf/hkdf/mod.rs
// Constant-time tests for HKDF (HMAC-based Key Derivation Function)

use tests::suites::constant_time::config::TestConfig;
use tests::suites::constant_time::tester::{TimingTester, generate_test_insights};
use algorithms::hash::Sha256;
use algorithms::kdf::hkdf::Hkdf;
use algorithms::kdf::KeyDerivationFunction;

// Helper function instead of impl
fn create_hkdf_config() -> TestConfig {
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
fn test_hkdf_constant_time() {
    let config = create_hkdf_config(); // Using helper function
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