use dcrypt_primitives::{
    // Import from crate root instead of types module
    Nonce12,
    Digest32,
    hash::{HashFunction, Sha256},
    types::Salt,
};

fn main() {
    // Type-safe nonce example
    let nonce = Nonce12::new([0x42; 12]);
    println!("Nonce: {:?}", nonce);
    
    // Type-safe hash example
    let digest = Sha256::digest(b"Hello, type system!").unwrap();
    println!("Digest: {:?}", digest);
    
    // Type-safe salt example
    let mut rng = rand::thread_rng();
    let salt = Salt::random_with_size(&mut rng, 16).unwrap();
    println!("Salt: {:?}", salt);
}