// File: crates/kem/benches/ecdh_comparison.rs
//! Comparison benchmarks for all ECDH-KEM implementations

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, PlotConfiguration, AxisScale};
use api::Kem;
use rand::rngs::OsRng;

// Import all ECDH implementations
use kem::ecdh::p192::EcdhP192;
use kem::ecdh::p224::EcdhP224;
use kem::ecdh::p256::EcdhP256;
use kem::ecdh::p384::EcdhP384;
use kem::ecdh::p521::EcdhP521;
use kem::ecdh::k256::EcdhK256;
use kem::ecdh::b283k::EcdhB283k;

fn bench_ecdh_keypair_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-Keypair-Comparison");
    let mut rng = OsRng;
    
    group.bench_function("P-192", |b| {
        b.iter(|| EcdhP192::keypair(&mut rng).unwrap());
    });
    
    group.bench_function("P-224", |b| {
        b.iter(|| EcdhP224::keypair(&mut rng).unwrap());
    });
    
    group.bench_function("P-256", |b| {
        b.iter(|| EcdhP256::keypair(&mut rng).unwrap());
    });
    
    group.bench_function("P-384", |b| {
        b.iter(|| EcdhP384::keypair(&mut rng).unwrap());
    });
    
    group.bench_function("P-521", |b| {
        b.iter(|| EcdhP521::keypair(&mut rng).unwrap());
    });
    
    group.bench_function("K-256", |b| {
        b.iter(|| EcdhK256::keypair(&mut rng).unwrap());
    });
    
    group.bench_function("B-283k", |b| {
        b.iter(|| EcdhB283k::keypair(&mut rng).unwrap());
    });
    
    group.finish();
}

fn bench_ecdh_encapsulate_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-Encapsulate-Comparison");
    let mut rng = OsRng;
    
    // Pre-generate public keys for each curve
    let (pk_p192, _) = EcdhP192::keypair(&mut rng).unwrap();
    let (pk_p224, _) = EcdhP224::keypair(&mut rng).unwrap();
    let (pk_p256, _) = EcdhP256::keypair(&mut rng).unwrap();
    let (pk_p384, _) = EcdhP384::keypair(&mut rng).unwrap();
    let (pk_p521, _) = EcdhP521::keypair(&mut rng).unwrap();
    let (pk_k256, _) = EcdhK256::keypair(&mut rng).unwrap();
    let (pk_b283k, _) = EcdhB283k::keypair(&mut rng).unwrap();
    
    group.bench_function("P-192", |b| {
        b.iter(|| EcdhP192::encapsulate(&mut rng, &pk_p192).unwrap());
    });
    
    group.bench_function("P-224", |b| {
        b.iter(|| EcdhP224::encapsulate(&mut rng, &pk_p224).unwrap());
    });
    
    group.bench_function("P-256", |b| {
        b.iter(|| EcdhP256::encapsulate(&mut rng, &pk_p256).unwrap());
    });
    
    group.bench_function("P-384", |b| {
        b.iter(|| EcdhP384::encapsulate(&mut rng, &pk_p384).unwrap());
    });
    
    group.bench_function("P-521", |b| {
        b.iter(|| EcdhP521::encapsulate(&mut rng, &pk_p521).unwrap());
    });
    
    group.bench_function("K-256", |b| {
        b.iter(|| EcdhK256::encapsulate(&mut rng, &pk_k256).unwrap());
    });
    
    group.bench_function("B-283k", |b| {
        b.iter(|| EcdhB283k::encapsulate(&mut rng, &pk_b283k).unwrap());
    });
    
    group.finish();
}

fn bench_ecdh_decapsulate_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-Decapsulate-Comparison");
    let mut rng = OsRng;
    
    // Pre-generate keypairs and ciphertexts for each curve
    let (pk_p192, sk_p192) = EcdhP192::keypair(&mut rng).unwrap();
    let (ct_p192, _) = EcdhP192::encapsulate(&mut rng, &pk_p192).unwrap();
    
    let (pk_p224, sk_p224) = EcdhP224::keypair(&mut rng).unwrap();
    let (ct_p224, _) = EcdhP224::encapsulate(&mut rng, &pk_p224).unwrap();
    
    let (pk_p256, sk_p256) = EcdhP256::keypair(&mut rng).unwrap();
    let (ct_p256, _) = EcdhP256::encapsulate(&mut rng, &pk_p256).unwrap();
    
    let (pk_p384, sk_p384) = EcdhP384::keypair(&mut rng).unwrap();
    let (ct_p384, _) = EcdhP384::encapsulate(&mut rng, &pk_p384).unwrap();
    
    let (pk_p521, sk_p521) = EcdhP521::keypair(&mut rng).unwrap();
    let (ct_p521, _) = EcdhP521::encapsulate(&mut rng, &pk_p521).unwrap();
    
    let (pk_k256, sk_k256) = EcdhK256::keypair(&mut rng).unwrap();
    let (ct_k256, _) = EcdhK256::encapsulate(&mut rng, &pk_k256).unwrap();
    
    let (pk_b283k, sk_b283k) = EcdhB283k::keypair(&mut rng).unwrap();
    let (ct_b283k, _) = EcdhB283k::encapsulate(&mut rng, &pk_b283k).unwrap();
    
    group.bench_function("P-192", |b| {
        b.iter(|| EcdhP192::decapsulate(&sk_p192, &ct_p192).unwrap());
    });
    
    group.bench_function("P-224", |b| {
        b.iter(|| EcdhP224::decapsulate(&sk_p224, &ct_p224).unwrap());
    });
    
    group.bench_function("P-256", |b| {
        b.iter(|| EcdhP256::decapsulate(&sk_p256, &ct_p256).unwrap());
    });
    
    group.bench_function("P-384", |b| {
        b.iter(|| EcdhP384::decapsulate(&sk_p384, &ct_p384).unwrap());
    });
    
    group.bench_function("P-521", |b| {
        b.iter(|| EcdhP521::decapsulate(&sk_p521, &ct_p521).unwrap());
    });
    
    group.bench_function("K-256", |b| {
        b.iter(|| EcdhK256::decapsulate(&sk_k256, &ct_k256).unwrap());
    });
    
    group.bench_function("B-283k", |b| {
        b.iter(|| EcdhB283k::decapsulate(&sk_b283k, &ct_b283k).unwrap());
    });
    
    group.finish();
}

fn bench_ecdh_throughput_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-Throughput-Operations-per-Second");
    group.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));
    
    let mut rng = OsRng;
    let iterations = 1000;
    
    // Benchmark operations per second for each curve
    group.bench_function("P-192", |b| {
        b.iter(|| {
            for _ in 0..iterations {
                let (pk, sk) = EcdhP192::keypair(&mut rng).unwrap();
                let (ct, _) = EcdhP192::encapsulate(&mut rng, &pk).unwrap();
                let _ = EcdhP192::decapsulate(&sk, &ct).unwrap();
            }
        });
    });
    
    group.bench_function("P-224", |b| {
        b.iter(|| {
            for _ in 0..iterations {
                let (pk, sk) = EcdhP224::keypair(&mut rng).unwrap();
                let (ct, _) = EcdhP224::encapsulate(&mut rng, &pk).unwrap();
                let _ = EcdhP224::decapsulate(&sk, &ct).unwrap();
            }
        });
    });
    
    group.bench_function("P-256", |b| {
        b.iter(|| {
            for _ in 0..iterations {
                let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();
                let (ct, _) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
                let _ = EcdhP256::decapsulate(&sk, &ct).unwrap();
            }
        });
    });
    
    group.bench_function("P-384", |b| {
        b.iter(|| {
            for _ in 0..iterations {
                let (pk, sk) = EcdhP384::keypair(&mut rng).unwrap();
                let (ct, _) = EcdhP384::encapsulate(&mut rng, &pk).unwrap();
                let _ = EcdhP384::decapsulate(&sk, &ct).unwrap();
            }
        });
    });
    
    group.bench_function("P-521", |b| {
        b.iter(|| {
            for _ in 0..iterations {
                let (pk, sk) = EcdhP521::keypair(&mut rng).unwrap();
                let (ct, _) = EcdhP521::encapsulate(&mut rng, &pk).unwrap();
                let _ = EcdhP521::decapsulate(&sk, &ct).unwrap();
            }
        });
    });
    
    group.bench_function("K-256", |b| {
        b.iter(|| {
            for _ in 0..iterations {
                let (pk, sk) = EcdhK256::keypair(&mut rng).unwrap();
                let (ct, _) = EcdhK256::encapsulate(&mut rng, &pk).unwrap();
                let _ = EcdhK256::decapsulate(&sk, &ct).unwrap();
            }
        });
    });
    
    group.bench_function("B-283k", |b| {
        b.iter(|| {
            for _ in 0..iterations {
                let (pk, sk) = EcdhB283k::keypair(&mut rng).unwrap();
                let (ct, _) = EcdhB283k::encapsulate(&mut rng, &pk).unwrap();
                let _ = EcdhB283k::decapsulate(&sk, &ct).unwrap();
            }
        });
    });
    
    group.finish();
}

fn print_ecdh_sizes() {
    println!("\n=== ECDH-KEM Key and Ciphertext Sizes ===\n");
    
    let mut rng = OsRng;
    
    // P-192
    let (pk_p192, sk_p192) = EcdhP192::keypair(&mut rng).unwrap();
    let (ct_p192, ss_p192) = EcdhP192::encapsulate(&mut rng, &pk_p192).unwrap();
    println!("P-192:");
    println!("  Public key:    {:3} bytes", pk_p192.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_p192.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_p192.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_p192.as_ref().len());
    
    // P-224
    let (pk_p224, sk_p224) = EcdhP224::keypair(&mut rng).unwrap();
    let (ct_p224, ss_p224) = EcdhP224::encapsulate(&mut rng, &pk_p224).unwrap();
    println!("\nP-224:");
    println!("  Public key:    {:3} bytes", pk_p224.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_p224.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_p224.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_p224.as_ref().len());
    
    // P-256
    let (pk_p256, sk_p256) = EcdhP256::keypair(&mut rng).unwrap();
    let (ct_p256, ss_p256) = EcdhP256::encapsulate(&mut rng, &pk_p256).unwrap();
    println!("\nP-256:");
    println!("  Public key:    {:3} bytes", pk_p256.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_p256.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_p256.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_p256.as_ref().len());
    
    // P-384
    let (pk_p384, sk_p384) = EcdhP384::keypair(&mut rng).unwrap();
    let (ct_p384, ss_p384) = EcdhP384::encapsulate(&mut rng, &pk_p384).unwrap();
    println!("\nP-384:");
    println!("  Public key:    {:3} bytes", pk_p384.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_p384.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_p384.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_p384.as_ref().len());
    
    // P-521
    let (pk_p521, sk_p521) = EcdhP521::keypair(&mut rng).unwrap();
    let (ct_p521, ss_p521) = EcdhP521::encapsulate(&mut rng, &pk_p521).unwrap();
    println!("\nP-521:");
    println!("  Public key:    {:3} bytes", pk_p521.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_p521.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_p521.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_p521.as_ref().len());
    
    // K-256
    let (pk_k256, sk_k256) = EcdhK256::keypair(&mut rng).unwrap();
    let (ct_k256, ss_k256) = EcdhK256::encapsulate(&mut rng, &pk_k256).unwrap();
    println!("\nK-256 (secp256k1):");
    println!("  Public key:    {:3} bytes", pk_k256.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_k256.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_k256.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_k256.as_ref().len());
    
    // B-283k
    let (pk_b283k, sk_b283k) = EcdhB283k::keypair(&mut rng).unwrap();
    let (ct_b283k, ss_b283k) = EcdhB283k::encapsulate(&mut rng, &pk_b283k).unwrap();
    println!("\nB-283k (sect283k1):");
    println!("  Public key:    {:3} bytes", pk_b283k.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_b283k.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_b283k.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_b283k.as_ref().len());
    
    println!("\n=========================================\n");
}

fn setup_and_print_sizes(_: &mut Criterion) {
    print_ecdh_sizes();
}

criterion_group!(
    benches,
    setup_and_print_sizes,
    bench_ecdh_keypair_comparison,
    bench_ecdh_encapsulate_comparison,
    bench_ecdh_decapsulate_comparison,
    bench_ecdh_throughput_comparison
);

criterion_main!(benches);