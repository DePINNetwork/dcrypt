use algorithms::{
    Nonce,
    Digest,
    hash::{HashFunction, Sha256},
    types::Salt,
};

fn main() {
    // Type-safe nonce example using generic parameter
    let nonce = Nonce::<12>::new([0x42; 12]);
    println!("Nonce: {:?}", nonce);
    
    // Type-safe hash example - Sha256 already produces a Digest<32>
    let digest = Sha256::digest(b"Hello, type system!").unwrap();
    println!("Digest: {:?}", digest);
    
    // Type-safe salt example with explicit type annotation
    let mut rng = rand::thread_rng();
    let salt: Salt<16> = Salt::random_with_size(&mut rng, 16).unwrap();
    println!("Salt: {:?}", salt);
}