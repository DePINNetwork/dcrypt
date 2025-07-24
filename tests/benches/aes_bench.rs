use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use dcrypt_algorithms::block::aes::{Aes128, Aes192, Aes256};
use dcrypt_algorithms::block::modes::cbc::Cbc;
use dcrypt_algorithms::types::{SecretBytes, Nonce};
use dcrypt_algorithms::block::BlockCipher;

fn bench_aes_cbc(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-CBC");
    
    // Test different data sizes
    for size in [16, 256, 1024, 16384].iter() {
        let data = vec![0u8; *size];
        let iv = Nonce::<16>::new([0u8; 16]);
        
        // AES-128
        group.bench_with_input(
            BenchmarkId::new("AES-128", size),
            size,
            |b, _| {
                let key = SecretBytes::<16>::new([0u8; 16]);
                let cipher = Aes128::new(&key);
                let cbc = Cbc::new(cipher, &iv).unwrap();
                b.iter(|| {
                    let _ = cbc.encrypt(&data);
                });
            }
        );
        
        // AES-192
        group.bench_with_input(
            BenchmarkId::new("AES-192", size),
            size,
            |b, _| {
                let key = SecretBytes::<24>::new([0u8; 24]);
                let cipher = Aes192::new(&key);
                let cbc = Cbc::new(cipher, &iv).unwrap();
                b.iter(|| {
                    let _ = cbc.encrypt(&data);
                });
            }
        );
        
        // AES-256
        group.bench_with_input(
            BenchmarkId::new("AES-256", size),
            size,
            |b, _| {
                let key = SecretBytes::<32>::new([0u8; 32]);
                let cipher = Aes256::new(&key);
                let cbc = Cbc::new(cipher, &iv).unwrap();
                b.iter(|| {
                    let _ = cbc.encrypt(&data);
                });
            }
        );
    }
    
    group.finish();
}

fn bench_aes_mct(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-CBC-MCT");
    
    let data = vec![0u8; 16]; // Single block for MCT
    let iterations = 1000; // MCT iteration count
    
    // Benchmark MCT with key schedule reuse vs without
    group.bench_function("AES-128-MCT-optimized", |b| {
        let key = SecretBytes::<16>::new([0u8; 16]);
        let cipher = Aes128::new(&key); // Create once
        
        b.iter(|| {
            let mut iv = [0u8; 16];
            let mut pt = data.clone();
            
            for i in 0..iterations {
                let iv_nonce = Nonce::<16>::new(iv);
                let cbc = Cbc::new(cipher.clone(), &iv_nonce).unwrap();
                let ct = cbc.encrypt(&pt).unwrap();
                
                // Update for next iteration
                iv.copy_from_slice(&ct[ct.len()-16..]);
                pt = ct;
            }
        });
    });
    
    group.bench_function("AES-128-MCT-naive", |b| {
        let key = SecretBytes::<16>::new([0u8; 16]);
        
        b.iter(|| {
            let mut iv = [0u8; 16];
            let mut pt = data.clone();
            
            for i in 0..iterations {
                // Create cipher every iteration (naive approach)
                let cipher = Aes128::new(&key);
                let iv_nonce = Nonce::<16>::new(iv);
                let cbc = Cbc::new(cipher, &iv_nonce).unwrap();
                let ct = cbc.encrypt(&pt).unwrap();
                
                // Update for next iteration
                iv.copy_from_slice(&ct[ct.len()-16..]);
                pt = ct;
            }
        });
    });
    
    group.finish();
}

criterion_group!(benches, bench_aes_cbc, bench_aes_mct);
criterion_main!(benches);