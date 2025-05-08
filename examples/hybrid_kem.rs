//! Example using hybrid KEM (RSA + Kyber)

use dcrypt::prelude::*;
use dcrypt::kem::RsaKyberHybrid;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hybrid KEM Example (RSA + Kyber)");
    println!("================================");
    
    // Generate a random number generator
    let mut rng = OsRng;
    
    // Generate keypair for hybrid KEM
    println!("Generating hybrid keypair...");
    let (public_key, secret_key) = RsaKyberHybrid::keypair(&mut rng)?;
    
    // Encapsulate a shared secret
    println!("Encapsulating shared secret...");
    let (ciphertext, shared_secret_sender) = RsaKyberHybrid::encapsulate(&mut rng, &public_key)?;
    
    // Print shared secret (sender side)
    println!("Sender's shared secret (first 8 bytes): {:?}", &shared_secret_sender.as_ref()[..8]);
    
    // Decapsulate the shared secret
    println!("Decapsulating shared secret...");
    let shared_secret_recipient = RsaKyberHybrid::decapsulate(&secret_key, &ciphertext)?;
    
    // Print shared secret (recipient side)
    println!("Recipient's shared secret (first 8 bytes): {:?}", &shared_secret_recipient.as_ref()[..8]);
    
    // Verify that both sides have the same shared secret
    assert_eq!(
        shared_secret_sender.as_ref(),
        shared_secret_recipient.as_ref()
    );
    
    println!("Shared secrets match! ✓");
    println!("\nBenefits of hybrid KEM:");
    println!("1. Classical security from RSA");
    println!("2. Quantum resistance from Kyber");
    println!("3. Combined shared secret provides stronger key material");
    
    Ok(())
}
