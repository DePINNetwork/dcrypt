// tests/constant_time/mac_tests.rs
// Constant-time tests for MAC (Message Authentication Code) algorithms

use tests::suites::constant_time::config::TestConfig;
use tests::suites::constant_time::tester::{TimingTester, generate_test_insights};
use algorithms::hash::Sha256;
use algorithms::mac::hmac::Hmac;

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