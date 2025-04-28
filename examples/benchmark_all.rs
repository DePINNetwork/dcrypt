//! Benchmark for all algorithms

use dcrypt::prelude::*;
use dcrypt::kem::{RsaKem2048, Kyber768, NtruHps};
use dcrypt::sign::{Ed25519, Dilithium3, Falcon512};
use dcrypt::symmetric::{Aes256Gcm, ChaCha20Poly1305};
use dcrypt::hybrid::kem::RsaKyberHybrid;
use dcrypt::hybrid::sign::EcdsaDilithiumHybrid;
use rand::rngs::OsRng;
use std::time::{Duration, Instant};

fn benchmark<F, R>(name: &str, iterations: usize, f: F) -> Duration
where
    F: Fn() -> R,
{
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _ = f();
    }
    
    let duration = start.elapsed();
    let avg_duration = duration / iterations as u32;
    
    println!("{}: {:?} (avg per operation)", name, avg_duration);
    
    duration
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("DCRYPT Algorithm Benchmarks");
    println!("==========================");
    
    let mut rng = OsRng;
    
    println!("\nKEM Key Generation (1 iteration):");
    benchmark("RSA-2048", 1, || RsaKem2048::keypair(&mut rng).unwrap());
    benchmark("Kyber-768", 1, || Kyber768::keypair(&mut rng).unwrap());
    benchmark("NTRU-HPS", 1, || NtruHps::keypair(&mut rng).unwrap());
    benchmark("RSA+Kyber Hybrid", 1, || RsaKyberHybrid::keypair(&mut rng).unwrap());
    
    println!("\nSignature Key Generation (1 iteration):");
    benchmark("Ed25519", 1, || Ed25519::keypair(&mut rng).unwrap());
    benchmark("Dilithium3", 1, || Dilithium3::keypair(&mut rng).unwrap());
    benchmark("Falcon-512", 1, || Falcon512::keypair(&mut rng).unwrap());
    benchmark("ECDSA+Dilithium Hybrid", 1, || EcdsaDilithiumHybrid::keypair(&mut rng).unwrap());
    
    // For KEM encapsulation/decapsulation and signature generation/verification,
    // we would first need to generate keys, then perform the operations.
    // In a real benchmark, this would be implemented.
    
    println!("\nNote: This is a skeleton benchmark. In a real implementation, it would include:");
    println!("- KEM encapsulation/decapsulation");
    println!("- Signature generation/verification");
    println!("- Symmetric encryption/decryption");
    println!("- More iterations for statistical accuracy");
    
    Ok(())
}
