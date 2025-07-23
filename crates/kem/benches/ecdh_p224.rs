// File: crates/kem/benches/ecdh_p224.rs
//! Benchmarks for ECDH-P224 KEM operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BatchSize};
use kem::ecdh::p224::{EcdhP224, EcdhP224PublicKey, EcdhP224SecretKey, EcdhP224Ciphertext};
use api::Kem;
use rand::rngs::OsRng;

fn bench_p224_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_p224_keypair");
    
    group.bench_function("generate", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let (pk, sk) = EcdhP224::keypair(&mut rng).unwrap();
            black_box(pk);
            black_box(sk);
        });
    });
    
    group.finish();
}

fn bench_p224_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_p224_encapsulate");
    let mut rng = OsRng;
    
    // Generate a recipient keypair for benchmarking
    let (recipient_pk, _) = EcdhP224::keypair(&mut rng).unwrap();
    
    group.bench_function("single", |b| {
        b.iter(|| {
            let (ct, ss) = EcdhP224::encapsulate(&mut rng, &recipient_pk).unwrap();
            black_box(ct);
            black_box(ss);
        });
    });
    
    // Benchmark with different batch sizes
    for batch_size in [10, 100, 1000] {
        group.bench_function(format!("batch_{}", batch_size), |b| {
            b.iter_batched(
                || recipient_pk.clone(),
                |pk| {
                    for _ in 0..batch_size {
                        let (ct, ss) = EcdhP224::encapsulate(&mut rng, &pk).unwrap();
                        black_box(ct);
                        black_box(ss);
                    }
                },
                BatchSize::SmallInput
            );
        });
    }
    
    group.finish();
}

fn bench_p224_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_p224_decapsulate");
    let mut rng = OsRng;
    
    // Generate a recipient keypair and a ciphertext
    let (recipient_pk, recipient_sk) = EcdhP224::keypair(&mut rng).unwrap();
    let (ciphertext, _) = EcdhP224::encapsulate(&mut rng, &recipient_pk).unwrap();
    
    group.bench_function("single", |b| {
        b.iter(|| {
            let ss = EcdhP224::decapsulate(&recipient_sk, &ciphertext).unwrap();
            black_box(ss);
        });
    });
    
    // Benchmark with different batch sizes
    for batch_size in [10, 100, 1000] {
        group.bench_function(format!("batch_{}", batch_size), |b| {
            b.iter_batched(
                || (recipient_sk.clone(), ciphertext.clone()),
                |(sk, ct)| {
                    for _ in 0..batch_size {
                        let ss = EcdhP224::decapsulate(&sk, &ct).unwrap();
                        black_box(ss);
                    }
                },
                BatchSize::SmallInput
            );
        });
    }
    
    group.finish();
}

fn bench_p224_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_p224_roundtrip");
    let mut rng = OsRng;
    
    group.bench_function("complete", |b| {
        b.iter(|| {
            // Generate recipient keypair
            let (recipient_pk, recipient_sk) = EcdhP224::keypair(&mut rng).unwrap();
            
            // Encapsulate
            let (ciphertext, ss_sender) = EcdhP224::encapsulate(&mut rng, &recipient_pk).unwrap();
            
            // Decapsulate
            let ss_recipient = EcdhP224::decapsulate(&recipient_sk, &ciphertext).unwrap();
            
            // Return values to prevent optimization
            black_box(ss_sender);
            black_box(ss_recipient);
        });
    });
    
    group.finish();
}

fn bench_p224_parallel_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_p224_parallel");
    let mut rng = OsRng;
    
    // Benchmark multiple recipients scenario
    group.bench_function("multi_recipient_10", |b| {
        // Pre-generate 10 recipient keypairs
        let recipients: Vec<_> = (0..10)
            .map(|_| EcdhP224::keypair(&mut rng).unwrap())
            .collect();
        
        b.iter(|| {
            // Encapsulate to all recipients
            for (pk, _) in &recipients {
                let (ct, ss) = EcdhP224::encapsulate(&mut rng, pk).unwrap();
                black_box(ct);
                black_box(ss);
            }
        });
    });
    
    // Benchmark single recipient, multiple messages scenario
    group.bench_function("single_recipient_multi_msg_10", |b| {
        let (recipient_pk, recipient_sk) = EcdhP224::keypair(&mut rng).unwrap();
        
        b.iter(|| {
            let mut ciphertexts = Vec::with_capacity(10);
            
            // Encapsulate 10 times to same recipient
            for _ in 0..10 {
                let (ct, ss) = EcdhP224::encapsulate(&mut rng, &recipient_pk).unwrap();
                ciphertexts.push(ct);
                black_box(ss);
            }
            
            // Decapsulate all
            for ct in &ciphertexts {
                let ss = EcdhP224::decapsulate(&recipient_sk, ct).unwrap();
                black_box(ss);
            }
        });
    });
    
    group.finish();
}

fn bench_p224_key_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_p224_sizes");
    let mut rng = OsRng;
    
    group.bench_function("measure_sizes", |b| {
        b.iter(|| {
            let (pk, sk) = EcdhP224::keypair(&mut rng).unwrap();
            let (ct, ss) = EcdhP224::encapsulate(&mut rng, &pk).unwrap();
            
            // Measure sizes (these will be optimized away, but we want to ensure
            // the compiler doesn't optimize away the entire computation)
            let pk_size = pk.as_ref().len();
            let sk_size = sk.as_ref().len();
            let ct_size = ct.as_ref().len();
            let ss_size = ss.as_ref().len();
            
            black_box(pk_size);
            black_box(sk_size);
            black_box(ct_size);
            black_box(ss_size);
        });
    });
    
    group.finish();
}

// Benchmark authenticated vs non-authenticated operations
// (P-224 includes authentication tags)
fn bench_p224_auth_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_p224_auth");
    let mut rng = OsRng;
    
    // Generate test data
    let (pk, sk) = EcdhP224::keypair(&mut rng).unwrap();
    
    // Benchmark encapsulation (includes tag generation)
    group.bench_function("encapsulate_with_auth", |b| {
        b.iter(|| {
            let (ct, ss) = EcdhP224::encapsulate(&mut rng, &pk).unwrap();
            black_box(ct);
            black_box(ss);
        });
    });
    
    // Benchmark decapsulation (includes tag verification)
    let (ct, _) = EcdhP224::encapsulate(&mut rng, &pk).unwrap();
    group.bench_function("decapsulate_with_auth", |b| {
        b.iter(|| {
            let ss = EcdhP224::decapsulate(&sk, &ct).unwrap();
            black_box(ss);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_p224_keypair,
    bench_p224_encapsulate,
    bench_p224_decapsulate,
    bench_p224_roundtrip,
    bench_p224_parallel_operations,
    bench_p224_key_sizes,
    bench_p224_auth_overhead
);
criterion_main!(benches);