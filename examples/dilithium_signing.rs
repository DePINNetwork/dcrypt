//! Example using Dilithium signatures

use dcrypt::prelude::*;
use dcrypt::sign::Dilithium3;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Dilithium3 Signature Example (Post-Quantum)");
    println!("==========================================");
    
    // Generate a random number generator
    let mut rng = OsRng;
    
    // Generate keypair for Dilithium
    println!("Generating Dilithium3 keypair...");
    let (public_key, secret_key) = Dilithium3::keypair(&mut rng)?;
    
    // Message to sign
    let message = b"This message will be secure even against quantum computers";
    println!("Message: {:?}", std::str::from_utf8(message)?);
    
    // Sign the message
    println!("Signing message with Dilithium3...");
    let signature = Dilithium3::sign(message, &secret_key)?;
    
    // Verify the signature
    println!("Verifying Dilithium3 signature...");
    Dilithium3::verify(message, &signature, &public_key)?;
    
    println!("Signature verified! ✓");
    println!("\nDilithium3 provides post-quantum security against:");
    println!("- Shor's algorithm");
    println!("- Grover's algorithm");
    println!("- Other known quantum attacks");
    
    Ok(())
}
