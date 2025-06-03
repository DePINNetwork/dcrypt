// tests/constant_time/kdf/pbkdf2/mod.rs
// Constant-time tests for PBKDF2 (Password-Based Key Derivation Function 2)

use tests::suites::constant_time::config::TestConfig;
use tests::suites::constant_time::tester::{TimingTester, generate_test_insights};
use algorithms::hash::Sha256;
use algorithms::kdf::pbkdf2::Pbkdf2;
use algorithms::kdf::KeyDerivationFunction;

// Helper function instead of impl
fn create_pbkdf2_config() -> TestConfig {
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
fn test_pbkdf2_constant_time() {
    let config = create_pbkdf2_config(); // Using helper function
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