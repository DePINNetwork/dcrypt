//! Example using RSA-KEM

use dcrypt::prelude::*;
use dcrypt::kem::RsaKem2048;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("RSA-KEM Example");
    println!("===============");
    
    // Generate a random number generator
    let mut rng = OsRng;
    
    // Generate keypair for RSA-KEM
    println!("Generating RSA-KEM keypair...");
    let (public_key, secret_key) = RsaKem2048::keypair(&mut rng)?;
    
    // Encapsulate a shared secret
    println!("Encapsulating shared secret...");
    let (ciphertext, shared_secret_sender) = RsaKem2048::encapsulate(&mut rng, &public_key)?;
    
    // Print shared secret (sender side)
    println!("Sender's shared secret: {:?}", &shared_secret_sender.as_ref()[..8]);
    
    // Decapsulate the shared secret
    println!("Decapsulating shared secret...");
    let shared_secret_recipient = RsaKem2048::decapsulate(&secret_key, &ciphertext)?;
    
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
