//! Benchmark for all algorithms

use dcrypt::prelude::*;
use dcrypt::kem::{RsaKem2048, Kyber768, NtruHps};
use dcrypt::sign::{Ed25519, Dilithium3, Falcon512};
use dcrypt::symmetric::{Aes256Gcm, ChaCha20Poly1305};
use dcrypt::hybrid::kem::RsaKyberHybrid;
use dcrypt::hybrid::sign::EcdsaDilithiumHybrid;
use rand::rngs::OsRng;
use std::time::{Duration, Instant};

// A custom error type for benchmarking
#[derive(Debug)]
enum BenchmarkError {
    KeygenError(String),
    EncapsulationError(String),
    SigningError(String),
    EncryptionError(String),
}

impl std::fmt::Display for BenchmarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchmarkError::KeygenError(msg) => write!(f, "Key generation error: {}", msg),
            BenchmarkError::EncapsulationError(msg) => write!(f, "Encapsulation error: {}", msg),
            BenchmarkError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            BenchmarkError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
        }
    }
}

impl std::error::Error for BenchmarkError {}

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

// Benchmarks a function that returns a Result
fn benchmark_result<F, R, E>(name: &str, iterations: usize, mut f: F) -> Result<Duration, E>
where
    F: FnMut() -> Result<R, E>,
    E: std::fmt::Debug,
{
    let start = Instant::now();
    
    for i in 0..iterations {
        if let Err(e) = f() {
            println!("Error on iteration {}: {:?}", i, e);
            return Err(e);
        }
    }
    
    let duration = start.elapsed();
    let avg_duration = duration / iterations as u32;
    
    println!("{}: {:?} (avg per operation)", name, avg_duration);
    
    Ok(duration)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("DCRYPT Algorithm Benchmarks");
    println!("==========================");
    
    let mut rng = OsRng;
    
    println!("\nKEM Key Generation (1 iteration):");
    
    // Using our result benchmark for RsaKem2048
    benchmark_result("RSA-2048", 1, || {
        RsaKem2048::keypair(&mut rng)
            .map_err(|e| BenchmarkError::KeygenError(format!("RSA-2048: {}", e)))
    })?;
    
    // For simplicity, we could also use the original benchmark function
    // with a closure that handles the error internally
    benchmark("Kyber-768", 1, || {
        match Kyber768::keypair(&mut rng) {
            Ok(keypair) => keypair,
            Err(e) => {
                // In a real app, you'd handle this better, but for a benchmark,
                // logging and continuing with a default might be acceptable
                eprintln!("Kyber-768 keypair generation failed: {}", e);
                panic!("Benchmark error - see log for details");
            }
        }
    });
    
    // Using the non-result benchmark for the remaining operations,
    // but with proper error handling in the closure
    benchmark("NTRU-HPS", 1, || {
        NtruHps::keypair(&mut rng)
            .map_err(|e| {
                eprintln!("NTRU-HPS keypair generation failed: {}", e);
                Box::<dyn std::error::Error>::from(format!("{}", e))
            })
            .unwrap_or_else(|_| panic!("Benchmark failed - see log for details"))
    });
    
    benchmark("RSA+Kyber Hybrid", 1, || {
        RsaKyberHybrid::keypair(&mut rng)
            .map_err(|e| {
                eprintln!("RSA+Kyber hybrid keypair generation failed: {}", e);
                e
            })
            .unwrap_or_else(|_| panic!("Benchmark failed - see log for details"))
    });
    
    println!("\nSignature Key Generation (1 iteration):");
    benchmark_result("Ed25519", 1, || {
        Ed25519::keypair(&mut rng)
            .map_err(|e| BenchmarkError::KeygenError(format!("Ed25519: {}", e)))
    })?;
    
    benchmark_result("Dilithium3", 1, || {
        Dilithium3::keypair(&mut rng)
            .map_err(|e| BenchmarkError::KeygenError(format!("Dilithium3: {}", e)))
    })?;
    
    benchmark_result("Falcon-512", 1, || {
        Falcon512::keypair(&mut rng)
            .map_err(|e| BenchmarkError::KeygenError(format!("Falcon-512: {}", e)))
    })?;
    
    benchmark_result("ECDSA+Dilithium Hybrid", 1, || {
        EcdsaDilithiumHybrid::keypair(&mut rng)
            .map_err(|e| BenchmarkError::KeygenError(format!("ECDSA+Dilithium hybrid: {}", e)))
    })?;
    
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