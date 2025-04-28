//! Example using Kyber KEM

use dcrypt::prelude::*;
use dcrypt::kem::Kyber768;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Kyber-768 KEM Example");
    println!("====================");
    
    // Generate a random number generator
    let mut rng = OsRng;
    
    // Generate keypair for Kyber
    println!("Generating Kyber-768 keypair...");
    let (public_key, secret_key) = Kyber768::keypair(&mut rng)?;
    
    println!("Public key size: {} bytes", public_key.as_ref().len());
    println!("Secret key size: {} bytes", secret_key.as_ref().len());
    
    // Encapsulate a shared secret
    println!("Encapsulating shared secret...");
    let (ciphertext, shared_secret_sender) = Kyber768::encapsulate(&mut rng, &public_key)?;
    
    println!("Ciphertext size: {} bytes", ciphertext.as_ref().len());
    println!("Shared secret size: {} bytes", shared_secret_sender.as_ref().len());
    
    // Print shared secret (sender side)
    println!("Sender's shared secret: {:?}", &shared_secret_sender.as_ref()[..8]);
    
    // Decapsulate the shared secret
    println!("Decapsulating shared secret...");
    let shared_secret_recipient = Kyber768::decapsulate(&secret_key, &ciphertext)?;
    
    // Print shared secret (recipient side)
    println!("Recipient's shared secret: {:?}", &shared_secret_recipient.as_ref()[..8]);
    
    // Verify that both sides have the same shared secret
    assert_eq!(
        shared_secret_sender.as_ref(),
        shared_secret_recipient.as_ref()
    );
    
    println!("Shared secrets match! ✓");
    
    Ok(())
}
