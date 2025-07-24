// src/constant_time/tester.rs
use statrs::distribution::{ContinuousCDF, StudentsT};
use std::time::Instant;

// Structure to hold the results of timing analysis
#[derive(Debug)]
pub struct TimingAnalysis {
    pub mean_a: f64,
    pub mean_b: f64,
    pub std_dev_a: f64,
    pub std_dev_b: f64,
    pub mean_ratio: f64,
    pub t_statistic: f64,
    pub degrees_of_freedom: f64,
    pub p_value: f64,
    pub combined_score: f64,
    pub is_constant_time: bool,
    // Effect size measurements
    pub cohens_d: f64,
    pub effect_size_interpretation: String,
    pub confidence_interval: (f64, f64),
}

pub struct TimingTester {
    pub num_samples: usize,
    pub num_iterations: usize,
}

impl TimingTester {
    pub fn new(num_samples: usize, num_iterations: usize) -> Self {
        Self {
            num_samples,
            num_iterations,
        }
    }

    pub fn measure<F>(&self, mut f: F) -> Vec<u128>
    where
        F: FnMut(),
    {
        let mut times = Vec::with_capacity(self.num_samples);
        for _ in 0..self.num_samples {
            let start = Instant::now();
            for _ in 0..self.num_iterations {
                f();
            }
            let end = Instant::now();
            let avg = (end - start).as_nanos() / self.num_iterations as u128;
            times.push(avg);
        }
        times
    }

    pub fn mean(times: &[u128]) -> f64 {
        let sum: u128 = times.iter().sum();
        sum as f64 / times.len() as f64
    }

    pub fn variance(times: &[u128], mean: f64) -> f64 {
        let ss: f64 = times
            .iter()
            .map(|&t| {
                let d = t as f64 - mean;
                d * d
            })
            .sum();
        ss / (times.len() as f64 - 1.0)
    }

    // Remove outliers using IQR method
    pub fn remove_outliers(times: &[u128]) -> Vec<u128> {
        if times.len() < 4 {
            return times.to_vec(); // Not enough data for quartiles
        }

        // Sort to find quartiles
        let mut sorted = times.to_vec();
        sorted.sort();

        // Calculate quartile positions
        let q1_pos = (sorted.len() as f64 * 0.25) as usize;
        let q3_pos = (sorted.len() as f64 * 0.75) as usize;

        // Get quartile values
        let q1 = sorted[q1_pos] as f64;
        let q3 = sorted[q3_pos] as f64;

        // Calculate IQR and bounds
        let iqr = q3 - q1;
        let lower_bound = q1 - 1.5 * iqr;
        let upper_bound = q3 + 1.5 * iqr;

        // Filter out outliers
        times
            .iter()
            .filter(|&&t| (t as f64) >= lower_bound && (t as f64) <= upper_bound)
            .copied()
            .collect()
    }

    // Calculate t-statistic between two timing samples
    pub fn t_statistic(times_a: &[u128], times_b: &[u128]) -> f64 {
        let mean_a = Self::mean(times_a);
        let mean_b = Self::mean(times_b);
        let var_a = Self::variance(times_a, mean_a);
        let var_b = Self::variance(times_b, mean_b);
        let n_a = times_a.len() as f64;
        let n_b = times_b.len() as f64;

        // Welch's t-test formula
        (mean_a - mean_b).abs() / ((var_a / n_a + var_b / n_b).sqrt())
    }

    // Enhanced p-value calculation using proper t-distribution
    pub fn p_value(t_stat: f64, df: f64) -> f64 {
        // Handle edge cases
        if df < 1.0 || !df.is_finite() {
            return Self::fallback_p_value(t_stat);
        }

        // Create Student's t-distribution with df degrees of freedom
        match StudentsT::new(0.0, 1.0, df) {
            Ok(dist) => {
                // Calculate two-tailed p-value
                let p = 2.0 * (1.0 - dist.cdf(t_stat.abs()));
                // Ensure p-value is in valid range
                p.max(0.0).min(1.0)
            }
            Err(_) => Self::fallback_p_value(t_stat),
        }
    }

    // Fallback function for when distribution creation fails
    fn fallback_p_value(t_stat: f64) -> f64 {
        // Approximation for p-value based on t-statistic
        match t_stat.abs() {
            t if t < 0.1 => 0.92,
            t if t < 0.5 => 0.68,
            t if t < 1.0 => 0.45,
            t if t < 1.5 => 0.25,
            t if t < 2.0 => 0.12,
            t if t < 2.5 => 0.05,
            t if t < 3.0 => 0.02,
            _ => 0.01,
        }
    }

    // Calculate degrees of freedom for Welch's t-test
    pub fn degrees_of_freedom(times_a: &[u128], times_b: &[u128]) -> f64 {
        let mean_a = Self::mean(times_a);
        let mean_b = Self::mean(times_b);
        let var_a = Self::variance(times_a, mean_a);
        let var_b = Self::variance(times_b, mean_b);
        let n_a = times_a.len() as f64;
        let n_b = times_b.len() as f64;

        // Welch-Satterthwaite equation
        let term_a = var_a / n_a;
        let term_b = var_b / n_b;

        (term_a + term_b).powi(2) / (term_a.powi(2) / (n_a - 1.0) + term_b.powi(2) / (n_b - 1.0))
    }

    // Calculate Cohen's d effect size
    pub fn cohens_d(times_a: &[u128], times_b: &[u128]) -> f64 {
        let mean_a = Self::mean(times_a);
        let mean_b = Self::mean(times_b);
        let var_a = Self::variance(times_a, mean_a);
        let var_b = Self::variance(times_b, mean_b);
        let n_a = times_a.len() as f64;
        let n_b = times_b.len() as f64;

        // Pooled standard deviation calculation
        let pooled_std_dev =
            ((var_a * (n_a - 1.0) + var_b * (n_b - 1.0)) / (n_a + n_b - 2.0)).sqrt();

        // Cohen's d formula
        (mean_a - mean_b).abs() / pooled_std_dev
    }

    // Interpret Cohen's d value
    pub fn interpret_effect_size(d: f64) -> String {
        match d {
            d if d < 0.2 => "Negligible effect".to_string(),
            d if d < 0.5 => "Small effect".to_string(),
            d if d < 0.8 => "Medium effect".to_string(),
            d if d < 1.2 => "Large effect".to_string(),
            _ => "Very large effect".to_string(),
        }
    }

    // Helper function to get t-critical values
    pub fn t_critical_value(df: f64, confidence_level: f64) -> f64 {
        match StudentsT::new(0.0, 1.0, df) {
            Ok(dist) => {
                let alpha = 1.0 - confidence_level;
                dist.inverse_cdf(1.0 - alpha / 2.0)
            }
            Err(_) => {
                // Fallback approximation
                match confidence_level {
                    c if c >= 0.99 => 2.58,
                    c if c >= 0.98 => 2.33,
                    c if c >= 0.95 => 1.96,
                    c if c >= 0.90 => 1.64,
                    _ => 1.28,
                }
            }
        }
    }

    // Enhanced combined score that incorporates mean ratio, t-statistic, and variance
    pub fn combined_score(
        &self,
        mean_ratio: f64,
        _p_value: f64,
        t_stat: f64,
        rel_std_dev_a: f64,
        rel_std_dev_b: f64,
    ) -> f64 {
        // Use the maximum relative standard deviation
        let max_rel_std_dev = f64::max(rel_std_dev_a, rel_std_dev_b);

        // Define weights for each component
        let weight_mean_ratio = 0.5; // Primary weight
        let weight_t_stat = 0.2; // Lower weight for t-statistic
        let weight_std_dev = 0.3; // Medium weight for standard deviation

        // Calculate normalized score components
        let mean_ratio_component = (mean_ratio - 1.0) * weight_mean_ratio;
        let t_stat_component = (t_stat / 10.0) * weight_t_stat; // Normalize by dividing by 10
        let std_dev_component = max_rel_std_dev * weight_std_dev;

        // Combine all components
        let score = 1.0 + mean_ratio_component + t_stat_component + std_dev_component;

        // Ensure score is positive and reasonable
        if score.is_nan() || score.is_infinite() || score < 1.0 {
            mean_ratio
        } else {
            score
        }
    }

    // Complete analyze_constant_time method with new metrics
    pub fn analyze_constant_time(
        &self,
        times_a: &[u128],
        times_b: &[u128],
        _mean_ratio_max: f64,
        _t_stat_threshold: f64,
        combined_score_threshold: f64,
    ) -> Result<TimingAnalysis, String> {
        // Remove outliers
        let clean_a = Self::remove_outliers(times_a);
        let clean_b = Self::remove_outliers(times_b);

        if clean_a.is_empty() || clean_b.is_empty() {
            return Err("After outlier removal, not enough data points remain".to_string());
        }

        // Calculate statistics
        let mean_a = Self::mean(&clean_a);
        let mean_b = Self::mean(&clean_b);
        let var_a = Self::variance(&clean_a, mean_a);
        let var_b = Self::variance(&clean_b, mean_b);
        let std_dev_a = var_a.sqrt();
        let std_dev_b = var_b.sqrt();
        let n_a = clean_a.len() as f64;
        let n_b = clean_b.len() as f64;

        // Calculate mean ratio (ensuring it's >= 1)
        let mean_ratio = if mean_a > mean_b {
            mean_a / mean_b
        } else {
            mean_b / mean_a
        };

        // Calculate t-statistic
        let t_stat = Self::t_statistic(&clean_a, &clean_b);

        // Calculate degrees of freedom
        let df = Self::degrees_of_freedom(&clean_a, &clean_b);

        // Calculate p-value with enhanced function
        let p_value = Self::p_value(t_stat, df);

        // Calculate relative standard deviations
        let rel_std_dev_a = std_dev_a / mean_a;
        let rel_std_dev_b = std_dev_b / mean_b;

        // Calculate enhanced combined score
        let combined_score =
            self.combined_score(mean_ratio, p_value, t_stat, rel_std_dev_a, rel_std_dev_b);

        // New metrics: Cohen's d effect size
        let cohens_d = Self::cohens_d(&clean_a, &clean_b);
        let effect_size_interpretation = Self::interpret_effect_size(cohens_d);

        // Calculate confidence interval for mean difference
        let confidence_level = 0.95;
        let t_critical = Self::t_critical_value(df, confidence_level);
        let standard_error = ((var_a / n_a) + (var_b / n_b)).sqrt();
        let margin_of_error = t_critical * standard_error;
        let mean_diff = (mean_a - mean_b).abs();
        let confidence_interval = (
            (mean_diff - margin_of_error).max(0.0),
            mean_diff + margin_of_error,
        );

        // Create analysis results with new fields
        let analysis = TimingAnalysis {
            mean_a,
            mean_b,
            std_dev_a,
            std_dev_b,
            mean_ratio,
            t_statistic: t_stat,
            degrees_of_freedom: df,
            p_value,
            combined_score,
            is_constant_time: combined_score <= combined_score_threshold,
            // New fields
            cohens_d,
            effect_size_interpretation,
            confidence_interval,
        };

        Ok(analysis)
    }
}

/// Generates detailed insights for constant-time test results
/// Uses only statistical patterns to infer likely issues without algorithm-specific knowledge
pub fn generate_test_insights(
    analysis: &TimingAnalysis,
    _config: &crate::suites::constant_time::config::TestConfig,
    primitive_name: &str,
) -> String {
    let mut insights = String::new();

    // Calculate additional metrics for analysis
    let mean_diff = (analysis.mean_a - analysis.mean_b).abs();
    let timing_difference_percent =
        (mean_diff / f64::min(analysis.mean_a, analysis.mean_b)) * 100.0;
    let rel_std_dev_a = analysis.std_dev_a / analysis.mean_a;
    let rel_std_dev_b = analysis.std_dev_b / analysis.mean_b;
    let std_dev_ratio =
        f64::max(rel_std_dev_a, rel_std_dev_b) / f64::min(rel_std_dev_a, rel_std_dev_b);

    // Test status with minimal output for passing tests
    if analysis.is_constant_time {
        insights.push_str(&format!(
            "✅ PASS: {} implementation appears to be constant-time.\n",
            primitive_name
        ));
        return insights;
    }

    insights.push_str(&format!(
        "❌ FAIL: {} timing vulnerability detected.\n\n",
        primitive_name
    ));

    // Concise metrics summary - only the most relevant ones
    insights.push_str("📊 METRICS:\n");
    insights.push_str(&format!(
        "  Mean: {:.0} ns vs {:.0} ns (diff: {:.1}%)\n",
        analysis.mean_a, analysis.mean_b, timing_difference_percent
    ));
    insights.push_str(&format!(
        "  Stats: t={:.1}, p={:.2e}, d={:.1}\n\n",
        analysis.t_statistic, analysis.p_value, analysis.cohens_d
    ));

    // Pattern-based diagnosis with targeted fixes
    insights.push_str("🔍 TIMING PATTERNS:\n");

    let mut patterns_detected = false;

    // Pattern 1: Clear data-dependent branching
    if analysis.mean_ratio > 1.5 && analysis.t_statistic > 15.0 && analysis.p_value < 0.001 {
        patterns_detected = true;
        insights.push_str("🔍 Data-dependent execution paths\n");
        insights.push_str("  ⚠️ Significant timing ratio (1.9x) with high consistency suggests branching on input\n");
        insights.push_str("  🛠️ Replace conditional branches with constant-time operations\n");
    }

    // Pattern 2: Early returns or shortcuts
    if timing_difference_percent > 40.0 && analysis.cohens_d > 5.0 {
        patterns_detected = true;
        insights.push_str("🔍 Early-return optimization\n");
        insights.push_str(
            "  ⚠️ Large timing difference suggests operations being skipped for certain inputs\n",
        );
        insights.push_str("  🛠️ Ensure all operations execute regardless of input\n");
    }

    // Pattern 3: Variable iteration counts
    if std_dev_ratio > 4.0 && (rel_std_dev_a > 0.1 || rel_std_dev_b > 0.1) {
        patterns_detected = true;
        insights.push_str("🔍 Input-dependent iteration\n");
        insights.push_str(
            "  ⚠️ Disparity in timing variability indicates data-dependent loop counts\n",
        );
        insights.push_str("  🛠️ Fix loops to process fixed iterations regardless of input\n");
    }

    // Pattern 4: Subtle but consistent leaks
    if analysis.t_statistic > 15.0 && analysis.cohens_d < 1.5 && analysis.cohens_d > 0.8 {
        patterns_detected = true;
        insights.push_str("🔍 Subtle timing leak\n");
        insights.push_str("  ⚠️ Small but highly consistent timing difference detected\n");
        insights.push_str("  🛠️ Check for compiler optimizations or CPU-level effects\n");
    }

    // Pattern 5: Memory access patterns
    if (rel_std_dev_a < 0.05 && rel_std_dev_b < 0.05) && analysis.mean_ratio > 1.2 {
        patterns_detected = true;
        insights.push_str("🔍 Memory access timing variation\n");
        insights.push_str("  ⚠️ Consistent timing differences with low variability suggest memory access patterns\n");
        insights
            .push_str("  🛠️ Ensure data accesses follow fixed patterns independent of secrets\n");
    }

    // Add a fallback if no specific patterns were detected
    if !patterns_detected {
        insights.push_str("🔍 General timing inconsistency\n");
        insights
            .push_str("  ⚠️ Pattern doesn't match known signatures but timing is not constant\n");
        insights.push_str("  🛠️ Review for any data-dependent operations or optimizations\n");
    }

    // Add a brief exploitation assessment
    insights.push_str("\n🔥 EXPLOITABILITY: ");
    if timing_difference_percent > 70.0 && analysis.t_statistic > 20.0 {
        insights.push_str("HIGH - Easily measurable in remote contexts\n");
    } else if timing_difference_percent > 20.0 || analysis.t_statistic > 10.0 {
        insights.push_str("MEDIUM - Measurable with statistical techniques\n");
    } else {
        insights.push_str("LOW - Requires sophisticated measurement\n");
    }

    insights
}
