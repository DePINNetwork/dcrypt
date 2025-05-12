// This example demonstrates how the primitives can be used in a no_std environment
// even though it's being compiled with std available for testing purposes
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use algorithms::hash::{Blake2b, Blake2s, HashFunction, Sha256};
use algorithms::block::{Aes128, BlockCipher};
use algorithms::aead::Gcm;
use algorithms::mac::Poly1305;
use algorithms::types::{Nonce, Digest, SecretBytes};
use api::traits::{SymmetricCipher, AuthenticatedCipher};
use api::traits::symmetric::{EncryptOperation, DecryptOperation};
use algorithms::Error;

// Function to demonstrate hash usage
fn hash_example() -> Result<Digest<32>, Error> {
    let data = b"Hello, no_std world!";
    let mut hasher = Sha256::new();
    hasher.update(data)?;
    hasher.finalize()
}

// Function to demonstrate blake2 usage  
fn blake2_example() -> Result<(Digest<64>, Digest<32>), Error> {
    let data = b"Blake2 in no_std!";
    
    let digest_b = Blake2b::digest(data)?;
    let digest_s = Blake2s::digest(data)?;
    
    Ok((digest_b, digest_s))
}

// Function to demonstrate Poly1305
fn poly1305_example() -> Result<(), Error> {
    // Just demonstrate that Poly1305 can be instantiated
    let key = [0u8; 32];
    let _mac = Poly1305::new(&key)?;
    Ok(())
}

// Function to demonstrate AEAD encryption
fn aead_example() -> Result<Vec<u8>, Error> {
    let key_bytes = [0u8; 16]; // Would use proper key generation in real code
    let key = SecretBytes::new(key_bytes); // Create the SecretBytes wrapper
    let nonce = Nonce::<12>::new([0u8; 12]); // Would use random nonce in real code
    let data = b"Secret message";
    let aad_data = b"Additional authenticated data";
    
    let aes = Aes128::new(&key);
    let gcm = Gcm::new(aes, &nonce)?;
    
    // Use the internal_encrypt method which returns the correct error type
    let ciphertext = gcm.internal_encrypt(data, Some(aad_data))?;
    
    Ok(ciphertext)
}

fn main() {
    println!("DCRYPT Primitives no_std Usage Example");
    println!("=====================================");
    
    // Hash example
    match hash_example() {
        Ok(hash) => println!("SHA-256 hash: {}", hex::encode(&hash)),
        Err(e) => println!("Hash error: {:?}", e),
    }
    
    // Blake2 example
    match blake2_example() {
        Ok((blake2b, blake2s)) => {
            println!("Blake2b hash: {}", hex::encode(&blake2b));
            println!("Blake2s hash: {}", hex::encode(&blake2s));
        }
        Err(e) => println!("Blake2 error: {:?}", e),
    }
    
    // Poly1305 example
    match poly1305_example() {
        Ok(_) => println!("Poly1305 initialized successfully"),
        Err(e) => println!("Poly1305 error: {:?}", e),
    }
    
    // AEAD example
    match aead_example() {
        Ok(ciphertext) => println!("AEAD ciphertext: {}", hex::encode(&ciphertext)),
        Err(e) => println!("AEAD error: {:?}", e),
    }
}

// If you need to test actual no_std behavior, create a separate binary crate
// with the following in Cargo.toml:
//
// [package]
// name = "no_std_example"
// 
// [dependencies]
// dcrypt-primitives = { path = ".", default-features = false, features = ["alloc"] }
//
// [[bin]]
// name = "no_std_example"
// path = "examples/true_no_std.rs"
//
// And then use #![no_std] and #![no_main] attributes in that file.