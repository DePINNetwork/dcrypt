// tests/constant_time/stream_tests.rs
// Constant-time tests for stream ciphers

use tests::suites::constant_time::config::TestConfig;
use tests::suites::constant_time::tester::{TimingTester, generate_test_insights};
use dcrypt_algorithms::stream::chacha::chacha20::{ChaCha20, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE};
use dcrypt_algorithms::types::Nonce;

#[test]
fn test_chacha20_constant_time() {
    let config = TestConfig::for_stream();
    let key = [0x42u8; CHACHA20_KEY_SIZE];
    
    // Create a Nonce<12> from raw bytes
    let nonce_bytes = [0x24u8; CHACHA20_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20_NONCE_SIZE>::new(nonce_bytes);
    
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