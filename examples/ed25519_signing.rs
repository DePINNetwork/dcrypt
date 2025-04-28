//! Example using Ed25519 signatures

use dcrypt::prelude::*;
use dcrypt::sign::Ed25519;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Ed25519 Signature Example");
    println!("========================");
    
    // Generate a random number generator
    let mut rng = OsRng;
    
    // Generate keypair for Ed25519
    println!("Generating Ed25519 keypair...");
    let (public_key, secret_key) = Ed25519::keypair(&mut rng)?;
    
    println!("Public key size: {} bytes", public_key.as_ref().len());
    println!("Secret key size: {} bytes", secret_key.as_ref().len());
    
    // Message to sign
    let message = b"This is a test message that will be signed with Ed25519";
    println!("Message: {:?}", std::str::from_utf8(message)?);
    
    // Sign the message
    println!("Signing message...");
    let signature = Ed25519::sign(message, &secret_key)?;
    
    println!("Signature size: {} bytes", signature.as_ref().len());
    println!("Signature: {:?}", &signature.as_ref()[..8]);
    
    // Verify the signature
    println!("Verifying signature...");
    Ed25519::verify(message, &signature, &public_key)?;
    
    println!("Signature verified! ✓");
    
    // Try with a modified message
    let modified_message = b"This is a MODIFIED message that will NOT verify";
    println!("\nTrying with modified message...");
    println!("Modified message: {:?}", std::str::from_utf8(modified_message)?);
    
    match Ed25519::verify(modified_message, &signature, &public_key) {
        Ok(_) => println!("Signature incorrectly verified! ✗"),
        Err(e) => println!("Signature correctly failed verification: {}", e),
    }
    
    Ok(())
}
