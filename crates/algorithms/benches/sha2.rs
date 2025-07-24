use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dcrypt_algorithms::hash::sha2::{Sha512_224, Sha512_256};
use dcrypt_algorithms::hash::{HashFunction, Sha224, Sha256, Sha384, Sha512};

// Test data sizes
const SIZES: &[usize] = &[
    64,      // 1 block for SHA-256/224
    128,     // 2 blocks for SHA-256/224, 1 block for SHA-512/384
    256,     // 4 blocks for SHA-256/224, 2 blocks for SHA-512/384
    1024,    // 1 KB
    4096,    // 4 KB
    16384,   // 16 KB
    65536,   // 64 KB
    1048576, // 1 MB
];

fn bench_sha224(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-224");

    for &size in SIZES {
        let data = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha224::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });
    }

    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-256");

    for &size in SIZES {
        let data = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha256::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });
    }

    group.finish();
}

fn bench_sha384(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-384");

    for &size in SIZES {
        let data = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha384::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });
    }

    group.finish();
}

fn bench_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-512");

    for &size in SIZES {
        let data = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha512::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });
    }

    group.finish();
}

fn bench_sha512_224(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-512-224");

    for &size in SIZES {
        let data = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha512_224::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });
    }

    group.finish();
}

fn bench_sha512_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-512-256");

    for &size in SIZES {
        let data = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha512_256::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });
    }

    group.finish();
}

fn bench_sha2_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-2-incremental");

    // Test incremental hashing with multiple update calls
    let chunk_size = 4096; // 4KB chunks
    let total_size = 1048576; // 1MB total
    let data = vec![0u8; chunk_size];
    let chunks = total_size / chunk_size;

    group.throughput(Throughput::Bytes(total_size as u64));

    // SHA-256 incremental
    group.bench_function("SHA-256/1MB-incremental", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            for _ in 0..chunks {
                hasher.update(black_box(&data)).unwrap();
            }
            let digest = hasher.finalize().unwrap();
            black_box(digest);
        });
    });

    // SHA-512 incremental
    group.bench_function("SHA-512/1MB-incremental", |b| {
        b.iter(|| {
            let mut hasher = Sha512::new();
            for _ in 0..chunks {
                hasher.update(black_box(&data)).unwrap();
            }
            let digest = hasher.finalize().unwrap();
            black_box(digest);
        });
    });

    group.finish();
}

fn bench_sha2_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-2-comparison");

    // Compare all SHA-2 variants on the same data size
    let data_sizes = vec![1024, 16384, 1048576]; // 1KB, 16KB, 1MB

    for size in data_sizes {
        let data = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));

        // SHA-224
        group.bench_with_input(BenchmarkId::new("SHA-224", size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha224::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });

        // SHA-256
        group.bench_with_input(BenchmarkId::new("SHA-256", size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha256::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });

        // SHA-384
        group.bench_with_input(BenchmarkId::new("SHA-384", size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha384::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });

        // SHA-512
        group.bench_with_input(BenchmarkId::new("SHA-512", size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha512::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });

        // SHA-512/224
        group.bench_with_input(BenchmarkId::new("SHA-512/224", size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha512_224::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });

        // SHA-512/256
        group.bench_with_input(BenchmarkId::new("SHA-512/256", size), &data, |b, data| {
            b.iter(|| {
                let digest = Sha512_256::digest(black_box(data)).unwrap();
                black_box(digest);
            });
        });
    }

    group.finish();
}

// Test performance of the state initialization and finalization
fn bench_sha2_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-2-overhead");

    // Benchmark empty message hashing (measures init + finalize overhead)
    group.bench_function("SHA-256/empty", |b| {
        b.iter(|| {
            let digest = Sha256::digest(black_box(&[])).unwrap();
            black_box(digest);
        });
    });

    group.bench_function("SHA-512/empty", |b| {
        b.iter(|| {
            let digest = Sha512::digest(black_box(&[])).unwrap();
            black_box(digest);
        });
    });

    // Benchmark single block (just under block size to avoid second compression)
    let sha256_single_block = vec![0u8; 55]; // 64 - 9 bytes for padding
    let sha512_single_block = vec![0u8; 111]; // 128 - 17 bytes for padding

    group.bench_function("SHA-256/single-block", |b| {
        b.iter(|| {
            let digest = Sha256::digest(black_box(&sha256_single_block)).unwrap();
            black_box(digest);
        });
    });

    group.bench_function("SHA-512/single-block", |b| {
        b.iter(|| {
            let digest = Sha512::digest(black_box(&sha512_single_block)).unwrap();
            black_box(digest);
        });
    });

    group.finish();
}

// Test verify performance
fn bench_sha2_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-2-verify");

    let data_1kb = vec![0u8; 1024];
    let data_1mb = vec![0u8; 1048576];

    // Pre-compute digests
    let digest_256_1kb = Sha256::digest(&data_1kb).unwrap();
    let digest_256_1mb = Sha256::digest(&data_1mb).unwrap();
    let digest_512_1kb = Sha512::digest(&data_1kb).unwrap();
    let digest_512_1mb = Sha512::digest(&data_1mb).unwrap();

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("SHA-256/verify-1KB", |b| {
        b.iter(|| {
            let result = Sha256::verify(black_box(&data_1kb), black_box(&digest_256_1kb)).unwrap();
            black_box(result);
        });
    });

    group.throughput(Throughput::Bytes(1048576));
    group.bench_function("SHA-256/verify-1MB", |b| {
        b.iter(|| {
            let result = Sha256::verify(black_box(&data_1mb), black_box(&digest_256_1mb)).unwrap();
            black_box(result);
        });
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("SHA-512/verify-1KB", |b| {
        b.iter(|| {
            let result = Sha512::verify(black_box(&data_1kb), black_box(&digest_512_1kb)).unwrap();
            black_box(result);
        });
    });

    group.throughput(Throughput::Bytes(1048576));
    group.bench_function("SHA-512/verify-1MB", |b| {
        b.iter(|| {
            let result = Sha512::verify(black_box(&data_1mb), black_box(&digest_512_1mb)).unwrap();
            black_box(result);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sha224,
    bench_sha256,
    bench_sha384,
    bench_sha512,
    bench_sha512_224,
    bench_sha512_256,
    bench_sha2_incremental,
    bench_sha2_comparison,
    bench_sha2_overhead,
    bench_sha2_verify
);

criterion_main!(benches);
