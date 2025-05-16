// src/hash/shake/tests.rs

use super::*;
use hex;
use std::path::{Path, PathBuf};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")   // up to crates/
        .join("..")   // up to workspace root
        .join("tests")
        .join("src")
        .join("vectors")
        .join("shake")
}

#[test]
fn test_shake128_empty() {
    // NIST test vector: Empty string
    let expected = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
    
    let hash = Shake128::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[test]
fn test_shake128_abc() {
    // NIST test vector: "abc"
    let expected = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8";
    
    let hash = Shake128::digest(b"abc").unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[test]
fn test_shake256_empty() {
    // NIST test vector: Empty string
    let expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    
    let hash = Shake256::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

// This function handles NIST XOF test vectors with VARIABLE output lengths
fn run_shake_tests<H: HashFunction>(filepath: &str, name: &str)
where
    H::Output: AsRef<[u8]> + std::fmt::Debug {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;
    
    // Define ShakeTestVector locally since we can't access the one in xof::shake::tests
    struct ShakeTestVector {
        len: usize,        // Input length in bits
        msg: String,       // Hex-encoded message
        output_len: usize, // Length of output in bits
        output: String,    // Hex-encoded output (expected hash)
    }
    
    // Parse test vector file
    let file = match File::open(Path::new(filepath)) {
        Ok(f) => f,
        Err(_) => {
            println!("Test vector file not found: {}", filepath);
            println!("Please ensure the test vectors are in the correct directory.");
            return;
        }
    };
    
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let mut test_vectors = Vec::new();
    let mut current_vector: Option<ShakeTestVector> = None;
    
    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        if line.starts_with("Len = ") {
            // Start of a new test case
            if let Some(vector) = current_vector.take() {
                test_vectors.push(vector);
            }
            
            // Extract bit length
            let len = line[6..].parse::<usize>().unwrap();
            
            current_vector = Some(ShakeTestVector {
                len,
                msg: String::new(),
                output_len: 0,
                output: String::new(),
            });
        } else if line.starts_with("OutLen = ") {
            // Extract output length in bits
            if let Some(ref mut vector) = current_vector {
                vector.output_len = line[9..].parse::<usize>().unwrap();
            }
        } else if let Some(ref mut vector) = current_vector {
            // Parse test vector data
            if line.starts_with("Msg = ") {
                vector.msg = line[6..].to_string();
            } else if line.starts_with("Output = ") {
                vector.output = line[9..].to_string();
                
                // If OutLen wasn't specified, derive it from the output hex length
                if vector.output_len == 0 && !vector.output.is_empty() {
                    // Each hex character represents 4 bits
                    vector.output_len = vector.output.len() * 4;
                }
            }
        }
    }
    
    // Add the last test vector if present
    if let Some(vector) = current_vector {
        test_vectors.push(vector);
    }
    
    // Print statistics
    println!("Found {} test vectors in {}", test_vectors.len(), filepath);
    
    let mut tested = 0;
    let mut skipped = 0;
    let mut skipped_output_sizes = HashMap::new();  // Track skipped output sizes
    
    for (i, test) in test_vectors.iter().enumerate() {
        // Calculate expected output size in bytes
        let expected_output_bytes = if test.output_len == 0 {
            // When output_len is 0, infer from the actual output length
            // Divide by 2 since 2 hex characters = 1 byte
            test.output.len() / 2
        } else {
            test.output_len / 8
        };
        
        // Only test vectors with the right output size for our fixed-size implementation
        if expected_output_bytes != H::output_size() {
            skipped += 1;
            // Instead of printing each skip, count them by output size
            *skipped_output_sizes.entry(test.output_len).or_insert(0) += 1;
            continue;
        }
        
        // Process this test vector
        
        // Handle empty input case
        if test.len == 0 {
            let hash = H::digest(&[]).unwrap();
            let expected = hex::decode(&test.output).unwrap();
            assert_eq!(hash.as_ref(), expected.as_slice(), 
                "{} test case {} failed.", name, i);
            tested += 1;
            continue;
        }
        
        // Parse hex message
        let msg = if test.msg.is_empty() {
            Vec::new()
        } else {
            hex::decode(&test.msg).unwrap()
        };
        
        // Handle partial bytes for bit-length inputs
        if test.len % 8 != 0 {
            let bytes = test.len / 8;
            let bits = test.len % 8;
            
            if bytes < msg.len() {
                let mut truncated_msg = msg[..bytes].to_vec();
                if bits > 0 {
                    // Keep only specified bits in last byte
                    let mask = (1u8 << bits) - 1;
                    truncated_msg.push(msg[bytes] & mask);
                }
                
                let hash = H::digest(&truncated_msg).unwrap();
                let expected = hex::decode(&test.output).unwrap();
                assert_eq!(hash.as_ref(), expected.as_slice(), 
                    "{} test case {} failed.", name, i);
                tested += 1;
                continue;
            }
        }
        
        // Standard case - full bytes
        let hash = H::digest(&msg).unwrap();
        let expected = hex::decode(&test.output).unwrap();
        assert_eq!(hash.as_ref(), expected.as_slice(), 
            "{} test case {} failed.", name, i);
        tested += 1;
    }
    
    // Print summary
    println!("{} tests: {} passed, {} skipped", name, tested, skipped);
    
    // Print aggregated skip information
    if skipped > 0 {
        println!("Skipped test vectors by output size:");
        let mut sorted_sizes: Vec<_> = skipped_output_sizes.iter().collect();
        sorted_sizes.sort_by_key(|&(size, _)| *size);
        
        for (output_len, count) in sorted_sizes {
            println!("  - {} test vectors with {} bits output (expected {} bytes)", 
                     count, output_len, H::output_size());
        }
    }
}

#[test]
fn test_shake_nist_short_vectors() {
    // Get path to test vector directory
    let vectors_dir = vectors_dir();
    
    // Path to the test vector files - using Path::join for platform independence
    let shake_128_path = vectors_dir.join("SHAKE128ShortMsg.rsp");
    let shake_256_path = vectors_dir.join("SHAKE256ShortMsg.rsp");
    
    // Check if files exist and provide helpful message if they don't
    for path in [&shake_128_path, &shake_256_path] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }
    
    // Run tests - only matching the fixed output sizes
    run_shake_tests::<Shake128>(shake_128_path.to_str().unwrap(), "SHAKE-128");
    run_shake_tests::<Shake256>(shake_256_path.to_str().unwrap(), "SHAKE-256");
}

#[test]
fn test_shake_nist_long_vectors() {
    // Get path to test vector directory
    let vectors_dir = vectors_dir();
    
    // Path to the long message test vector files
    let shake_128_path = vectors_dir.join("SHAKE128LongMsg.rsp");
    let shake_256_path = vectors_dir.join("SHAKE256LongMsg.rsp");
    
    // Check if files exist and provide helpful message if they don't
    for path in [&shake_128_path, &shake_256_path] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }
    
    // Run tests - only matching the fixed output sizes
    run_shake_tests::<Shake128>(shake_128_path.to_str().unwrap(), "SHAKE-128");
    run_shake_tests::<Shake256>(shake_256_path.to_str().unwrap(), "SHAKE-256");
}