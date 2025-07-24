// Make the chacha20 module public
pub mod chacha20;
// Remove reference to non-existent chacha12 module

// Re-export for convenience
pub use chacha20::ChaCha20;
