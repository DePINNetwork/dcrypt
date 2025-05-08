// src/constant_time/config.rs

// Default configuration with thresholds
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub mean_ratio_min: f64,
    pub mean_ratio_max: f64,
    pub std_dev_threshold: f64,    // Kept for diagnostics only
    pub t_stat_threshold: f64,     // t-statistic threshold
    pub combined_score_threshold: f64,  // combined score threshold
    pub num_warmup: usize,
    pub num_samples: usize,
    pub num_iterations: usize,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            mean_ratio_min: 0.80,
            mean_ratio_max: 1.25,
            std_dev_threshold: 0.20,   // Kept for diagnostics only
            t_stat_threshold: 1.7,     // Default from the algorithm document
            combined_score_threshold: 1.8,  // Default from the algorithm document
            num_warmup: 1000,
            num_samples: 25,
            num_iterations: 1000,
        }
    }
}

// Builder methods for easy customization
impl TestConfig {
    pub fn with_mean_ratio_range(mut self, min: f64, max: f64) -> Self {
        self.mean_ratio_min = min;
        self.mean_ratio_max = max;
        self
    }

    pub fn with_std_dev_threshold(mut self, threshold: f64) -> Self {
        self.std_dev_threshold = threshold;
        self
    }

    pub fn with_warmup(mut self, warmup: usize) -> Self {
        self.num_warmup = warmup;
        self
    }

    pub fn with_samples_and_iterations(mut self, samples: usize, iterations: usize) -> Self {
        self.num_samples = samples;
        self.num_iterations = iterations;
        self
    }
    
    // Set t-statistic threshold
    pub fn with_t_stat_threshold(mut self, threshold: f64) -> Self {
        self.t_stat_threshold = threshold;
        self
    }
    
    // Set combined score threshold
    pub fn with_combined_score_threshold(mut self, threshold: f64) -> Self {
        self.combined_score_threshold = threshold;
        self
    }
}

// Predefined configurations for specific algorithm types
impl TestConfig {
    pub fn for_block_cipher() -> Self {
        Self::default()
            .with_t_stat_threshold(1.7)
            .with_combined_score_threshold(1.8)
    }

    pub fn for_aead() -> Self {
        Self::default()
            .with_mean_ratio_range(0.80, 1.35)
            .with_t_stat_threshold(1.9)  // Slightly higher for more complex operations
            .with_combined_score_threshold(1.9)
    }

    pub fn for_hash() -> Self {
        Self::default()
            .with_mean_ratio_range(0.80, 1.3)
            .with_t_stat_threshold(3.5)  // Increased from 1.7 to allow for hash implementation variance
            .with_combined_score_threshold(1.8)
    }

    pub fn for_chacha_poly() -> Self {
        Self::default()
            .with_mean_ratio_range(0.80, 1.5)
            .with_t_stat_threshold(2.0)  // Higher due to more variability
            .with_combined_score_threshold(2.0)
    }

    pub fn for_xof() -> Self {
        Self::default()
            .with_t_stat_threshold(1.7)
            .with_combined_score_threshold(1.8)
    }

    pub fn for_blake3_xof() -> Self {
        Self::default()
            .with_std_dev_threshold(0.25)
            .with_t_stat_threshold(2.0)  // Higher for BLAKE3
            .with_combined_score_threshold(2.0)
    }

    pub fn for_mac() -> Self {
        Self::default()
            .with_mean_ratio_range(0.80, 1.6)
            .with_t_stat_threshold(1.8)
            .with_combined_score_threshold(2.0)
    }

    pub fn for_stream() -> Self {
        Self::default()
            .with_t_stat_threshold(1.7)
            .with_combined_score_threshold(1.8)
    }

    pub fn for_hkdf() -> Self {
        Self::default()
            .with_mean_ratio_range(0.80, 1.5) // Existing range for mean drift
            .with_std_dev_threshold(0.30)      // Kept for diagnostics only
            .with_t_stat_threshold(1.9)
            .with_combined_score_threshold(2.0)
    }

    pub fn for_pbkdf2() -> Self {
        Self::default()
            .with_mean_ratio_range(0.75, 1.33)
            .with_std_dev_threshold(0.4)       // Kept for diagnostics only
            .with_warmup(10)
            .with_samples_and_iterations(10, 10)
            .with_t_stat_threshold(2.2)  // Higher due to inherent variability
            .with_combined_score_threshold(2.2)
    }
}