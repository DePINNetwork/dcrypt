// File: crates/kem/benches/ecdh_p192.rs
//! Benchmarks for ECDH-P192 KEM operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use kem::ecdh::p192::{EcdhP192, EcdhP192PublicKey, EcdhP192SecretKey, EcdhP192Ciphertext};
use dcrypt_api::Kem;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Benchmark keypair generation with OsRng
fn bench_keypair_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P192/keypair_generation");
    
    // Benchmark with OsRng (cryptographically secure)
    group.bench_function("OsRng", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let keypair = EcdhP192::keypair(&mut rng).unwrap();
            black_box(keypair);
        });
    });
    
    // Benchmark with ChaCha20Rng (deterministic, faster)
    group.bench_function("ChaCha20Rng", |b| {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        b.iter(|| {
            let keypair = EcdhP192::keypair(&mut rng).unwrap();
            black_box(keypair);
        });
    });
    
    group.finish();
}

/// Benchmark encapsulation operation
fn bench_encapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P192/encapsulation");
    let mut rng = OsRng;
    
    // Generate a recipient keypair for benchmarking
    let (recipient_pk, _) = EcdhP192::keypair(&mut rng).unwrap();
    
    // Benchmark with OsRng
    group.bench_function("OsRng", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let (ciphertext, shared_secret) = EcdhP192::encapsulate(&mut rng, &recipient_pk).unwrap();
            black_box((ciphertext, shared_secret));
        });
    });
    
    // Benchmark with ChaCha20Rng
    group.bench_function("ChaCha20Rng", |b| {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        b.iter(|| {
            let (ciphertext, shared_secret) = EcdhP192::encapsulate(&mut rng, &recipient_pk).unwrap();
            black_box((ciphertext, shared_secret));
        });
    });
    
    group.finish();
}

/// Benchmark decapsulation operation
fn bench_decapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P192/decapsulation");
    let mut rng = OsRng;
    
    // Generate recipient keypair and create a ciphertext
    let (recipient_pk, recipient_sk) = EcdhP192::keypair(&mut rng).unwrap();
    let (ciphertext, _) = EcdhP192::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            let shared_secret = EcdhP192::decapsulate(&recipient_sk, &ciphertext).unwrap();
            black_box(shared_secret);
        });
    });
    
    group.finish();
}

/// Benchmark full KEM cycle (encapsulate + decapsulate)
fn bench_full_kem_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P192/full_cycle");
    let mut rng = OsRng;
    
    // Pre-generate multiple recipient keypairs for testing
    let keypairs: Vec<_> = (0..10)
        .map(|_| EcdhP192::keypair(&mut rng).unwrap())
        .collect();
    
    group.bench_function("single_recipient", |b| {
        let mut rng = OsRng;
        let (pk, sk) = &keypairs[0];
        b.iter(|| {
            let (ciphertext, ss_enc) = EcdhP192::encapsulate(&mut rng, pk).unwrap();
            let ss_dec = EcdhP192::decapsulate(sk, &ciphertext).unwrap();
            black_box((ss_enc, ss_dec));
        });
    });
    
    group.bench_function("multiple_recipients", |b| {
        let mut rng = OsRng;
        let mut idx = 0;
        b.iter(|| {
            let (pk, sk) = &keypairs[idx % keypairs.len()];
            idx += 1;
            let (ciphertext, ss_enc) = EcdhP192::encapsulate(&mut rng, pk).unwrap();
            let ss_dec = EcdhP192::decapsulate(sk, &ciphertext).unwrap();
            black_box((ss_enc, ss_dec));
        });
    });
    
    group.finish();
}

/// Benchmark batch operations
fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P192/batch");
    let mut rng = OsRng;
    
    // Benchmark different batch sizes
    for batch_size in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("keypair_generation", batch_size),
            batch_size,
            |b, &size| {
                let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
                b.iter(|| {
                    let keypairs: Vec<_> = (0..size)
                        .map(|_| EcdhP192::keypair(&mut rng).unwrap())
                        .collect();
                    black_box(keypairs);
                });
            },
        );
        
        // Pre-generate recipient keypairs for encapsulation benchmarks
        let recipients: Vec<_> = (0..*batch_size)
            .map(|_| EcdhP192::keypair(&mut rng).unwrap())
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("encapsulation", batch_size),
            batch_size,
            |b, &size| {
                let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
                b.iter(|| {
                    let results: Vec<_> = (0..size)
                        .map(|i| {
                            let (pk, _) = &recipients[i % recipients.len()];
                            EcdhP192::encapsulate(&mut rng, pk).unwrap()
                        })
                        .collect();
                    black_box(results);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark serialization/deserialization overhead
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P192/serialization");
    let mut rng = OsRng;
    
    // Generate test data
    let (pk, sk) = EcdhP192::keypair(&mut rng).unwrap();
    let (ct, _) = EcdhP192::encapsulate(&mut rng, &pk).unwrap();
    
    // Benchmark public key serialization (it's already in compressed form)
    group.bench_function("public_key_clone", |b| {
        b.iter(|| {
            let pk_clone = pk.clone();
            black_box(pk_clone);
        });
    });
    
    // Benchmark secret key cloning
    group.bench_function("secret_key_clone", |b| {
        b.iter(|| {
            let sk_clone = sk.clone();
            black_box(sk_clone);
        });
    });
    
    // Benchmark ciphertext cloning
    group.bench_function("ciphertext_clone", |b| {
        b.iter(|| {
            let ct_clone = ct.clone();
            black_box(ct_clone);
        });
    });
    
    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P192/memory");
    let mut rng = OsRng;
    
    // Measure the cost of repeated allocations
    group.bench_function("repeated_keypair_alloc", |b| {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        b.iter(|| {
            for _ in 0..100 {
                let _ = EcdhP192::keypair(&mut rng).unwrap();
                // Keys are dropped here, testing allocation/deallocation pattern
            }
        });
    });
    
    // Measure the cost of keeping keys in memory
    group.bench_function("persistent_keypair_storage", |b| {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        b.iter(|| {
            let mut keypairs = Vec::with_capacity(100);
            for _ in 0..100 {
                keypairs.push(EcdhP192::keypair(&mut rng).unwrap());
            }
            black_box(keypairs);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_keypair_generation,
    bench_encapsulation,
    bench_decapsulation,
    bench_full_kem_cycle,
    bench_batch_operations,
    bench_serialization,
    bench_memory_patterns
);

criterion_main!(benches);