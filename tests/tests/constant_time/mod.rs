// tests/constant_time/mod.rs
// Main module file for constant-time tests

// Declare submodules
pub mod aead_tests;
pub mod block_cipher_tests;
pub mod hash_tests;
pub mod kdf;
pub mod mac_tests;
pub mod stream_tests;
pub mod xof_tests;

// Re-export common modules used by tests
pub use dcrypt_tests::suites::constant_time::config::TestConfig;
pub use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
