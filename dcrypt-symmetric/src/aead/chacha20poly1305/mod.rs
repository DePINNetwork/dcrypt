//! ChaCha20Poly1305 cipher implementations
//!
//! This module provides implementations of the ChaCha20Poly1305 authenticated
//! encryption with associated data (AEAD) algorithm.
//!
//! # Examples
//!
//! ```
//! use dcrypt_symmetric::aead::chacha20poly1305::{ChaCha20Poly1305Cipher, ChaCha20Poly1305Key};
//! use dcrypt_symmetric::cipher::{SymmetricCipher, Aead};
//!
//! // Generate a random key
//! let key = ChaCha20Poly1305Key::generate();
//!
//! // Create a cipher instance
//! let cipher = ChaCha20Poly1305Cipher::new(&key);
//!
//! // Encrypt some data
//! let plaintext = b"Secret message";
//! let nonce = ChaCha20Poly1305Cipher::generate_nonce();
//! let ciphertext = cipher.encrypt(&nonce, plaintext, None).unwrap();
//!
//! // Decrypt the data
//! let decrypted = cipher.decrypt(&nonce, &ciphertext, None).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! ## Key Derivation
//!
//! ```
//! use dcrypt_symmetric::aead::chacha20poly1305::{derive_chacha20poly1305_key, generate_salt};
//!
//! let password = b"my secure password";
//! let salt = generate_salt(16);
//! let iterations = 100_000;
//!
//! let key = derive_chacha20poly1305_key(password, &salt, iterations).unwrap();
//! ```
//!
//! ## Encrypted Package Format
//!
//! ```
//! use dcrypt_symmetric::aead::chacha20poly1305::{ChaCha20Poly1305Cipher, ChaCha20Poly1305Key, 
//!     ChaCha20Poly1305CiphertextPackage};
//! use dcrypt_symmetric::cipher::{SymmetricCipher, Aead};
//!
//! // Generate a random key
//! let key = ChaCha20Poly1305Key::generate();
//! let cipher = ChaCha20Poly1305Cipher::new(&key);
//!
//! // Encrypt to a package that includes the nonce
//! let plaintext = b"Secret message";
//! let package = cipher.encrypt_to_package(plaintext, None).unwrap();
//!
//! // The package can be serialized for storage or transmission
//! let serialized = package.to_string();
//!
//! // Later, deserialize and decrypt
//! let parsed_package = ChaCha20Poly1305CiphertextPackage::from_string(&serialized).unwrap();
//! let decrypted = cipher.decrypt_package(&parsed_package, None).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```

mod common;
mod cipher;
mod streaming;


// Re-export common types and functions
pub use common::{
    ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, ChaCha20Poly1305CiphertextPackage,
    derive_chacha20poly1305_key, generate_salt
};

// Re-export cipher implementations
pub use cipher::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher, XChaCha20Poly1305Nonce};

// Re-export streaming implementations
pub use streaming::{
    ChaCha20Poly1305EncryptStream, ChaCha20Poly1305DecryptStream,
    chacha20poly1305_encrypt, chacha20poly1305_decrypt,
    chacha20poly1305_encrypt_package, chacha20poly1305_decrypt_package,
    encrypt_file, decrypt_file
};

// Re-export from crate::cipher for convenience
pub use crate::cipher::{SymmetricCipher, Aead};