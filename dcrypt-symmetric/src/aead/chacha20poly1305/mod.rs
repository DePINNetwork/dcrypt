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
//! use dcrypt_symmetric::error::Result;
//!
//! // Function demonstrating proper error handling
//! fn encrypt_decrypt_example() -> Result<()> {
//!     // Generate a random key
//!     let key = ChaCha20Poly1305Key::generate();
//!
//!     // Create a cipher instance with proper error handling
//!     let cipher = ChaCha20Poly1305Cipher::new(&key)?;
//!
//!     // Encrypt some data
//!     let plaintext = b"Secret message";
//!     let nonce = ChaCha20Poly1305Cipher::generate_nonce();
//!     let ciphertext = cipher.encrypt(&nonce, plaintext, None)?;
//!
//!     // Decrypt the data
//!     let decrypted = cipher.decrypt(&nonce, &ciphertext, None)?;
//!     assert_eq!(decrypted, plaintext);
//!     
//!     Ok(())
//! }
//!
//! // In main functions or tests, you would handle the result
//! // encrypt_decrypt_example().expect("Example failed");
//! ```
//!
//! ## Key Derivation
//!
//! ```
//! use dcrypt_symmetric::aead::chacha20poly1305::{derive_chacha20poly1305_key, generate_salt};
//! use dcrypt_symmetric::error::Result;
//!
//! fn key_derivation_example() -> Result<()> {
//!     let password = b"my secure password";
//!     let salt = generate_salt(16);
//!     let iterations = 100_000;
//!
//!     let key = derive_chacha20poly1305_key(password, &salt, iterations)?;
//!     
//!     // Use the key for encryption...
//!     Ok(())
//! }
//! ```
//!
//! ## Encrypted Package Format
//!
//! ```
//! use dcrypt_symmetric::aead::chacha20poly1305::{ChaCha20Poly1305Cipher, ChaCha20Poly1305Key, 
//!     ChaCha20Poly1305CiphertextPackage};
//! use dcrypt_symmetric::cipher::{SymmetricCipher, Aead};
//! use dcrypt_symmetric::error::Result;
//!
//! fn package_example() -> Result<()> {
//!     // Generate a random key
//!     let key = ChaCha20Poly1305Key::generate();
//!     
//!     // Create a cipher instance with proper error handling
//!     let cipher = ChaCha20Poly1305Cipher::new(&key)?;
//!
//!     // Encrypt to a package that includes the nonce
//!     let plaintext = b"Secret message";
//!     let package = cipher.encrypt_to_package(plaintext, None)?;
//!
//!     // The package can be serialized for storage or transmission
//!     let serialized = package.to_string();
//!
//!     // Later, deserialize and decrypt
//!     let parsed_package = ChaCha20Poly1305CiphertextPackage::from_string(&serialized)?;
//!     let decrypted = cipher.decrypt_package(&parsed_package, None)?;
//!     assert_eq!(decrypted, plaintext);
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Streaming Encryption
//!
//! For streaming encryption of large data, see the `streaming::chacha20poly1305` module.
//! ```
//! use std::io::Cursor;
//! use dcrypt_symmetric::aead::chacha20poly1305::ChaCha20Poly1305Key;
//! use dcrypt_symmetric::streaming::{StreamingEncrypt, StreamingDecrypt};
//! use dcrypt_symmetric::streaming::chacha20poly1305::{
//!     ChaCha20Poly1305EncryptStream, ChaCha20Poly1305DecryptStream
//! };
//! use dcrypt_symmetric::error::Result;
//!
//! fn streaming_example() -> Result<()> {
//!     // Generate a random key
//!     let key = ChaCha20Poly1305Key::generate();
//!
//!     // Create an in-memory buffer for this example
//!     let mut encrypted = Vec::new();
//!
//!     // Create a streaming encryption context with proper error handling
//!     let mut stream = ChaCha20Poly1305EncryptStream::new(&mut encrypted, &key, None)?;
//!
//!     // Encrypt data in chunks
//!     stream.write(b"First chunk of data")?;
//!     stream.write(b"Second chunk of data")?;
//!
//!     // Finalize the stream
//!     let _ = stream.finalize()?;
//!
//!     // Now decrypt the data
//!     let mut reader = Cursor::new(encrypted);
//!     let mut stream = ChaCha20Poly1305DecryptStream::new(reader, &key, None)?;
//!
//!     // Read the decrypted data
//!     let mut buffer = [0u8; 1024];
//!     let bytes_read = stream.read(&mut buffer)?;
//!     
//!     // The decrypted data is now in buffer[..bytes_read]
//!     Ok(())
//! }
//! ```

mod common;
mod cipher;
// No longer need to include the streaming module here

// Re-export common types and functions
pub use common::{
    ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, ChaCha20Poly1305CiphertextPackage,
    derive_chacha20poly1305_key, generate_salt
};

// Re-export cipher implementations
pub use cipher::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher, XChaCha20Poly1305Nonce};

// Re-export from crate::cipher for convenience
pub use crate::cipher::{SymmetricCipher, Aead};