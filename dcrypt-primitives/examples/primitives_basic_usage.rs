use dcrypt_primitives::{
    aead::ChaCha20Poly1305,
    Nonce12,
};

fn main() {
    // Create a key and nonce
    let key_data = [0x42; 32];
    let nonce_data = [0x24; 12];
    
    // Create ChaCha20Poly1305 instance
    let cipher = ChaCha20Poly1305::new(&key_data);
    
    // Example plaintext and associated data
    let plaintext = b"Hello, DCRYPT!";
    let aad = b"Additional data";
    
    // Create a proper Nonce object instead of using raw array
    let nonce = Nonce12::new(nonce_data);
    
    // Encrypt using the nonce object
    let ciphertext = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();
    println!("Ciphertext: {:?}", ciphertext);
    
    // Decrypt using the nonce object
    let decrypted = cipher.decrypt(&nonce, &ciphertext, Some(aad)).unwrap();
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
}