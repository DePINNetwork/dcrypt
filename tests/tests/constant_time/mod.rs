// tests/constant_time/mod.rs
// Main module file for constant-time tests

// Declare submodules
pub mod block_cipher_tests;
pub mod aead_tests;
pub mod hash_tests;
pub mod xof_tests;
pub mod mac_tests;
pub mod stream_tests;
pub mod kdf;

// Re-export common modules used by tests
pub use tests::suites::constant_time::config::TestConfig;
pub use tests::suites::constant_time::tester::{TimingTester, generate_test_insights};