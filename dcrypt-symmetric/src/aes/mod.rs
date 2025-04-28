//! AES cipher implementations
//!
//! This module provides implementations of the Advanced Encryption Standard (AES)
//! block cipher with different key sizes (128-bit and 256-bit).

// Make the keys module public so it can be imported by other modules
pub mod keys;

// Re-export key types and functions
pub use keys::{
    Aes128Key, Aes256Key,
    derive_aes128_key, derive_aes256_key, generate_salt
};

// Re-export from aead::gcm module
pub use crate::aead::gcm::{
    Aes128Gcm, Aes256Gcm,
    Aes128GcmEncryptStream, Aes128GcmDecryptStream,
    Aes256GcmEncryptStream, Aes256GcmDecryptStream,
    GcmNonce, AesCiphertextPackage,
    aes128_encrypt, aes128_decrypt,
    aes128_encrypt_package, aes128_decrypt_package,
    aes256_encrypt, aes256_decrypt,
    aes256_encrypt_package, aes256_decrypt_package
};

// Re-export from crate::cipher for convenience
pub use crate::cipher::{SymmetricCipher, Aead};