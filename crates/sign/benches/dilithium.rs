//! Benchmarks for Dilithium digital signature algorithms (FIPS 204).
//!
//! This module benchmarks the performance of Dilithium2, Dilithium3, and Dilithium5
//! across key generation, signing, and verification operations with various message sizes.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use sign::pq::dilithium::{Dilithium2, Dilithium3, Dilithium5};
use api::Signature;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Message sizes to benchmark (in bytes)
const MESSAGE_SIZES: &[usize] = &[
    32,      // Small message (hash size)
    256,     // Medium message 
    1024,    // 1 KB
    4096,    // 4 KB
    16384,   // 16 KB
    65536,   // 64 KB
];

/// Benchmark key generation for all Dilithium parameter sets
fn bench_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium_keypair");
    
    // Fixed RNG for reproducibility
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    
    group.bench_function("dilithium2", |b| {
        b.iter(|| {
            let _ = black_box(Dilithium2::keypair(&mut rng).unwrap());
        });
    });
    
    group.bench_function("dilithium3", |b| {
        b.iter(|| {
            let _ = black_box(Dilithium3::keypair(&mut rng).unwrap());
        });
    });
    
    group.bench_function("dilithium5", |b| {
        b.iter(|| {
            let _ = black_box(Dilithium5::keypair(&mut rng).unwrap());
        });
    });
    
    group.finish();
}

/// Benchmark signing operations for different message sizes
fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium_sign");
    
    // Generate keypairs once
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (_, sk2) = Dilithium2::keypair(&mut rng).unwrap();
    let (_, sk3) = Dilithium3::keypair(&mut rng).unwrap();
    let (_, sk5) = Dilithium5::keypair(&mut rng).unwrap();
    
    for size in MESSAGE_SIZES {
        let message = vec![0x42u8; *size];
        
        group.bench_with_input(
            BenchmarkId::new("dilithium2", size),
            size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(Dilithium2::sign(&message, &sk2).unwrap());
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("dilithium3", size),
            size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(Dilithium3::sign(&message, &sk3).unwrap());
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("dilithium5", size),
            size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(Dilithium5::sign(&message, &sk5).unwrap());
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark verification operations for different message sizes
fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium_verify");
    
    // Generate keypairs and signatures once
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (pk2, sk2) = Dilithium2::keypair(&mut rng).unwrap();
    let (pk3, sk3) = Dilithium3::keypair(&mut rng).unwrap();
    let (pk5, sk5) = Dilithium5::keypair(&mut rng).unwrap();
    
    for size in MESSAGE_SIZES {
        let message = vec![0x42u8; *size];
        
        // Pre-compute signatures
        let sig2 = Dilithium2::sign(&message, &sk2).unwrap();
        let sig3 = Dilithium3::sign(&message, &sk3).unwrap();
        let sig5 = Dilithium5::sign(&message, &sk5).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("dilithium2", size),
            size,
            |b, _| {
                b.iter(|| {
                    black_box(Dilithium2::verify(&message, &sig2, &pk2).unwrap());
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("dilithium3", size),
            size,
            |b, _| {
                b.iter(|| {
                    black_box(Dilithium3::verify(&message, &sig3, &pk3).unwrap());
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("dilithium5", size),
            size,
            |b, _| {
                b.iter(|| {
                    black_box(Dilithium5::verify(&message, &sig5, &pk5).unwrap());
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark complete round-trip (keypair + sign + verify) operations
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium_roundtrip");
    
    let message = b"Test message for dilithium round-trip benchmark";
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    
    group.bench_function("dilithium2", |b| {
        b.iter(|| {
            let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();
            let sig = Dilithium2::sign(message, &sk).unwrap();
            black_box(Dilithium2::verify(message, &sig, &pk).unwrap());
        });
    });
    
    group.bench_function("dilithium3", |b| {
        b.iter(|| {
            let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();
            let sig = Dilithium3::sign(message, &sk).unwrap();
            black_box(Dilithium3::verify(message, &sig, &pk).unwrap());
        });
    });
    
    group.bench_function("dilithium5", |b| {
        b.iter(|| {
            let (pk, sk) = Dilithium5::keypair(&mut rng).unwrap();
            let sig = Dilithium5::sign(message, &sk).unwrap();
            black_box(Dilithium5::verify(message, &sig, &pk).unwrap());
        });
    });
    
    group.finish();
}

/// Benchmark serialization/deserialization operations
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium_serialization");
    
    // Generate test data
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let message = b"Test message for serialization benchmark";
    
    // Dilithium2
    let (pk2, sk2) = Dilithium2::keypair(&mut rng).unwrap();
    let sig2 = Dilithium2::sign(message, &sk2).unwrap();
    let pk2_bytes = pk2.to_bytes();
    let sk2_bytes = sk2.to_bytes();
    let sig2_bytes = sig2.to_bytes();
    
    // Dilithium3
    let (pk3, sk3) = Dilithium3::keypair(&mut rng).unwrap();
    let sig3 = Dilithium3::sign(message, &sk3).unwrap();
    let pk3_bytes = pk3.to_bytes();
    let sk3_bytes = sk3.to_bytes();
    let sig3_bytes = sig3.to_bytes();
    
    // Dilithium5
    let (pk5, sk5) = Dilithium5::keypair(&mut rng).unwrap();
    let sig5 = Dilithium5::sign(message, &sk5).unwrap();
    let pk5_bytes = pk5.to_bytes();
    let sk5_bytes = sk5.to_bytes();
    let sig5_bytes = sig5.to_bytes();
    
    // Benchmark public key deserialization
    group.bench_function("dilithium2_pk_deserialize", |b| {
        b.iter(|| {
            use sign::pq::dilithium::DilithiumPublicKey;
            let _ = black_box(DilithiumPublicKey::from_bytes(&pk2_bytes).unwrap());
        });
    });
    
    group.bench_function("dilithium3_pk_deserialize", |b| {
        b.iter(|| {
            use sign::pq::dilithium::DilithiumPublicKey;
            let _ = black_box(DilithiumPublicKey::from_bytes(&pk3_bytes).unwrap());
        });
    });
    
    group.bench_function("dilithium5_pk_deserialize", |b| {
        b.iter(|| {
            use sign::pq::dilithium::DilithiumPublicKey;
            let _ = black_box(DilithiumPublicKey::from_bytes(&pk5_bytes).unwrap());
        });
    });
    
    // Benchmark secret key deserialization
    group.bench_function("dilithium2_sk_deserialize", |b| {
        b.iter(|| {
            use sign::pq::dilithium::DilithiumSecretKey;
            let _ = black_box(DilithiumSecretKey::from_bytes(&sk2_bytes).unwrap());
        });
    });
    
    group.bench_function("dilithium3_sk_deserialize", |b| {
        b.iter(|| {
            use sign::pq::dilithium::DilithiumSecretKey;
            let _ = black_box(DilithiumSecretKey::from_bytes(&sk3_bytes).unwrap());
        });
    });
    
    group.bench_function("dilithium5_sk_deserialize", |b| {
        b.iter(|| {
            use sign::pq::dilithium::DilithiumSecretKey;
            let _ = black_box(DilithiumSecretKey::from_bytes(&sk5_bytes).unwrap());
        });
    });
    
    // Benchmark signature deserialization
    group.bench_function("dilithium2_sig_deserialize", |b| {
        b.iter(|| {
            use sign::pq::dilithium::DilithiumSignatureData;
            let _ = black_box(DilithiumSignatureData::from_bytes(&sig2_bytes).unwrap());
        });
    });
    
    group.bench_function("dilithium3_sig_deserialize", |b| {
        b.iter(|| {
            use sign::pq::dilithium::DilithiumSignatureData;
            let _ = black_box(DilithiumSignatureData::from_bytes(&sig3_bytes).unwrap());
        });
    });
    
    group.bench_function("dilithium5_sig_deserialize", |b| {
        b.iter(|| {
            use sign::pq::dilithium::DilithiumSignatureData;
            let _ = black_box(DilithiumSignatureData::from_bytes(&sig5_bytes).unwrap());
        });
    });
    
    group.finish();
}

/// Benchmark signing iteration counts (to measure rejection sampling overhead)
/// This benchmark signs the same message multiple times to get statistics on iteration counts
fn bench_signing_iterations(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium_signing_iterations");
    group.sample_size(100); // Run 100 iterations to get good statistics
    
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let message = b"Test message for iteration count benchmark";
    
    // Generate keypairs
    let (_, sk2) = Dilithium2::keypair(&mut rng).unwrap();
    let (_, sk3) = Dilithium3::keypair(&mut rng).unwrap();
    let (_, sk5) = Dilithium5::keypair(&mut rng).unwrap();
    
    // We'll use different messages to trigger different iteration counts
    let messages: Vec<Vec<u8>> = (0..10)
        .map(|i| format!("Message variant {}", i).into_bytes())
        .collect();
    
    group.bench_function("dilithium2_multi_sign", |b| {
        let mut msg_idx = 0;
        b.iter(|| {
            let msg = &messages[msg_idx % messages.len()];
            msg_idx += 1;
            let _ = black_box(Dilithium2::sign(msg, &sk2).unwrap());
        });
    });
    
    group.bench_function("dilithium3_multi_sign", |b| {
        let mut msg_idx = 0;
        b.iter(|| {
            let msg = &messages[msg_idx % messages.len()];
            msg_idx += 1;
            let _ = black_box(Dilithium3::sign(msg, &sk3).unwrap());
        });
    });
    
    group.bench_function("dilithium5_multi_sign", |b| {
        let mut msg_idx = 0;
        b.iter(|| {
            let msg = &messages[msg_idx % messages.len()];
            msg_idx += 1;
            let _ = black_box(Dilithium5::sign(msg, &sk5).unwrap());
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_keypair,
    bench_sign,
    bench_verify,
    bench_roundtrip,
    bench_serialization,
    bench_signing_iterations
);

criterion_main!(benches);