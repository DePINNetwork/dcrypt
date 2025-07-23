## Running the Benchmarks

### Run all benchmarks:
```bash
cd crates/algorithms
cargo bench
```

### Run specific benchmarks:
```bash
# Run only AES benchmarks
cargo bench --bench aes

# Run only AES-GCM benchmarks
cargo bench --bench aes_gcm

# Run specific benchmark groups
cargo bench -- aes_block_encrypt
cargo bench -- aes_gcm_encrypt
```

### Generate baseline for comparison:
```bash
cargo bench -- --save-baseline main
```

### Compare against baseline:
```bash
# Make your changes, then run:
cargo bench -- --baseline main
```

## Benchmark Groups

### AES Benchmarks (`aes.rs`)
- **aes_key_expansion**: Key schedule performance for AES-128/192/256
- **aes_block_encrypt**: Single block encryption performance
- **aes_block_decrypt**: Single block decryption performance
- **aes_multi_block_encrypt**: Multi-block encryption (ECB-like)
- **aes_parallel_blocks**: Parallel block processing simulation

### AES-GCM Benchmarks (`aes_gcm.rs`)
- **aes_gcm_setup**: GCM initialization overhead
- **aes_gcm_encrypt**: Encryption performance for various message sizes
- **aes_gcm_decrypt**: Decryption performance for various message sizes
- **aes_gcm_with_aad**: Performance impact of Additional Authenticated Data
- **aes_gcm_nonce_sizes**: Performance with different nonce sizes
- **aes_gcm_small_messages**: Performance for small messages (protocol-sized)

## Interpreting Results

Results are generated in `target/criterion/`:
- HTML reports: `target/criterion/report/index.html`
- Individual benchmark details in subdirectories

Key metrics to watch:
- **Throughput**: MB/s or GB/s for data processing
- **Time**: ns/iter for small operations
- **Variance**: Lower is better for consistent performance

## Performance Tips

1. **Compile with optimizations**:
   ```bash
   RUSTFLAGS="-C target-cpu=native" cargo bench --release
   ```

2. **Reduce system noise**:
   - Close unnecessary applications
   - Disable CPU frequency scaling
   - Run on a quiet system

3. **For production builds**, consider testing with:
   ```bash
   RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo bench
   ```

## Customizing Benchmarks

To add new test cases, modify the size arrays in the benchmark files:

```rust
// For different message sizes
let sizes = [64, 256, 1024, 4096, 16384, 65536];

// For different AAD sizes
let aad_sizes = [16, 64, 256, 1024];
```

## Baseline Performance Expectations

On modern hardware (e.g., Intel Core i7 with AES-NI):
- AES-128 block encryption: ~1-2 cycles/byte
- AES-GCM encryption: ~2-4 cycles/byte
- Key expansion: ~100-300 cycles

Without hardware acceleration:
- AES-128 block encryption: ~10-20 cycles/byte
- AES-GCM encryption: ~15-30 cycles/byte