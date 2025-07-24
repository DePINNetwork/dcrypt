pub mod chacha20poly1305;
pub mod gcm;

// Re-export for convenience
pub use gcm::{Aes128Gcm, Aes256Gcm};
// Update the re-exports to use the correct types
pub use chacha20poly1305::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher};
