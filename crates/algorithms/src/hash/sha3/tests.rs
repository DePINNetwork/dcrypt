use super::*;
use hex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")   // up to crates/
        .join("..")   // up to workspace root
        .join("tests")
        .join("src")
        .join("vectors")
        .join("sha3")
}

// Basic sanity check tests - keep these for quick development feedback
#[test]
fn test_sha3_256_empty() {
    // NIST test vector: Empty string
    let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    
    let hash = Sha3_256::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[test]
fn test_sha3_224_empty() {
    // NIST test vector: Empty string
    let expected = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    
    let hash = Sha3_224::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[test]
fn test_sha3_384_empty() {
    // NIST test vector: Empty string
    let expected = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    
    let hash = Sha3_384::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[test]
fn test_sha3_512_empty() {
    // NIST test vector: Empty string
    let expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    
    let hash = Sha3_512::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[derive(Debug)]
struct Sha3TestVector {
    len: usize,   // Bit length
    msg: String,  // Hex-encoded message
    md: String,   // Hex-encoded digest (expected hash)
}

fn parse_sha3_test_file(filepath: &str) -> Vec<Sha3TestVector> {
    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let mut test_vectors = Vec::new();
    let mut current_vector: Option<Sha3TestVector> = None;
    
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
            
            current_vector = Some(Sha3TestVector {
                len,
                msg: String::new(),
                md: String::new(),
            });
        } else if let Some(ref mut vector) = current_vector {
            // Parse test vector data
            if line.starts_with("Msg = ") {
                vector.msg = line[6..].to_string();
            } else if line.starts_with("MD = ") {
                vector.md = line[5..].to_string();
            }
        }
    }
    
    // Add the last test vector if present
    if let Some(vector) = current_vector {
        test_vectors.push(vector);
    }
    
    test_vectors
}

// Modified with trait bounds to handle the type comparison
fn run_sha3_tests<H: HashFunction>(filepath: &str, name: &str) {
    let test_vectors = parse_sha3_test_file(filepath);
    
    for (i, test) in test_vectors.iter().enumerate() {
        // Check if bit length is 0
        if test.len == 0 {
            // If bit length is 0, use an empty message regardless of what's in the msg field
            let hash = H::digest(&[]).unwrap();
            
            // Convert expected hash to bytes
            let expected = hex::decode(&test.md).unwrap_or_else(|_| 
                panic!("Invalid hex in expected result {}: {}", i, test.md));
            
            // Convert the hash to Vec<u8> before comparison
            let hash_vec = hash.as_ref().to_vec();
            
            // Compare results
            assert_eq!(hash_vec, expected, 
                "{} test case {} failed. Input: empty, Expected: {}, Got: {}", 
                name, i, test.md, hex::encode(&hash));
            
            continue;
        }
        
        // For non-zero bit lengths, convert hex string to bytes and proceed as before
        let msg = if test.msg.is_empty() {
            Vec::new()
        } else {
            hex::decode(&test.msg).unwrap_or_else(|_| 
                panic!("Invalid hex in test vector {}: {}", i, test.msg))
        };
        
        // Handle partial bytes if bit length is not a multiple of 8
        if test.len % 8 != 0 {
            let bytes = test.len / 8;
            let bits = test.len % 8;
            
            if bytes < msg.len() {
                let mut truncated_msg = msg[..bytes].to_vec();
                if bits > 0 {
                    // Keep only the specified number of bits in the last byte
                    let mask = (1u8 << bits) - 1;
                    truncated_msg.push(msg[bytes] & mask);
                }
                let hash = H::digest(&truncated_msg).unwrap();
                
                // Convert expected hash to bytes
                let expected = hex::decode(&test.md).unwrap_or_else(|_| 
                    panic!("Invalid hex in expected result {}: {}", i, test.md));
                
                // Convert the hash to Vec<u8> before comparison
                let hash_vec = hash.as_ref().to_vec();
                
                // Compare results
                assert_eq!(hash_vec, expected, 
                    "{} test case {} failed. Input: {}, Expected: {}, Got: {}", 
                    name, i, test.msg, test.md, hex::encode(&hash));
                
                continue;
            }
        }
        
        // Hash the message
        let hash = H::digest(&msg).unwrap();
        
        // Convert expected hash to bytes
        let expected = hex::decode(&test.md).unwrap_or_else(|_| 
            panic!("Invalid hex in expected result {}: {}", i, test.md));
        
        // Convert the hash to Vec<u8> before comparison
        let hash_vec = hash.as_ref().to_vec();
        
        // Compare results
        assert_eq!(hash_vec, expected, 
            "{} test case {} failed. Input: {}, Expected: {}, Got: {}", 
            name, i, test.msg, test.md, hex::encode(&hash));
    }
}


#[test]
fn test_sha3_nist_short_vectors() {
    let dir = vectors_dir();
    
    // Path to the test vector files
    let sha3_224_path = dir.join("SHA3_224ShortMsg.rsp");
    let sha3_256_path = dir.join("SHA3_256ShortMsg.rsp");
    let sha3_384_path = dir.join("SHA3_384ShortMsg.rsp");
    let sha3_512_path = dir.join("SHA3_512ShortMsg.rsp");
    
    // Check if files exist and FAIL if they don't
    for path in [&sha3_224_path, &sha3_256_path, &sha3_384_path, &sha3_512_path] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }
    
    // Run the tests
    run_sha3_tests::<Sha3_224>(sha3_224_path.to_str().unwrap(), "SHA3-224");
    run_sha3_tests::<Sha3_256>(sha3_256_path.to_str().unwrap(), "SHA3-256");
    run_sha3_tests::<Sha3_384>(sha3_384_path.to_str().unwrap(), "SHA3-384");
    run_sha3_tests::<Sha3_512>(sha3_512_path.to_str().unwrap(), "SHA3-512");
}

#[test]
fn test_sha3_nist_long_vectors() {
    let dir = vectors_dir();
    
    // Path to the long message test vector files
    let sha3_224_path = dir.join("SHA3_224LongMsg.rsp");
    let sha3_256_path = dir.join("SHA3_256LongMsg.rsp");
    let sha3_384_path = dir.join("SHA3_384LongMsg.rsp");
    let sha3_512_path = dir.join("SHA3_512LongMsg.rsp");
    
    // Check if files exist and FAIL if they don't
    for path in [&sha3_224_path, &sha3_256_path, &sha3_384_path, &sha3_512_path] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }
    
    // Run the same test functions for long messages
    run_sha3_tests::<Sha3_224>(sha3_224_path.to_str().unwrap(), "SHA3-224");
    run_sha3_tests::<Sha3_256>(sha3_256_path.to_str().unwrap(), "SHA3-256");
    run_sha3_tests::<Sha3_384>(sha3_384_path.to_str().unwrap(), "SHA3-384");
    run_sha3_tests::<Sha3_512>(sha3_512_path.to_str().unwrap(), "SHA3-512");
}

#[derive(Debug)]
struct Sha3MonteTestVector {
    seed: String,      // Initial seed
    count: usize,      // Number of iterations
    expected: String   // Expected final MD value
}

fn parse_sha3_monte_test_file(filepath: &str) -> Vec<Sha3MonteTestVector> {
    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let mut test_vectors = Vec::new();
    let mut current_seed = String::new();
    let mut current_expected = String::new();
    let mut count = 0;
    
    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        if line.starts_with("Seed = ") {
            // Start of a new test case
            if !current_seed.is_empty() && !current_expected.is_empty() {
                test_vectors.push(Sha3MonteTestVector {
                    seed: current_seed.clone(),
                    count,
                    expected: current_expected.clone(),
                });
            }
            
            current_seed = line[7..].to_string();
            current_expected = String::new();
            count = 0;
        } else if line.starts_with("COUNT = ") {
            let count_str = line[8..].trim();
            count = count_str.parse::<usize>().unwrap_or(0);
        } else if line.starts_with("MD = ") && count == 100 { // Last iteration
            current_expected = line[5..].to_string();
        }
    }
    
    // Add the last test vector if present
    if !current_seed.is_empty() && !current_expected.is_empty() {
        test_vectors.push(Sha3MonteTestVector {
            seed: current_seed,
            count,
            expected: current_expected,
        });
    }
    
    test_vectors
}

// Modified to convert the hash function output to Vec<u8>
fn run_sha3_monte_tests<H: HashFunction>(filepath: &str, name: &str) {
    let test_vectors = parse_sha3_monte_test_file(filepath);
    
    for (i, test) in test_vectors.iter().enumerate() {
        // Convert seed to bytes
        let seed_bytes = hex::decode(&test.seed).unwrap_or_else(|_| 
            panic!("{} Monte Carlo test {}: Invalid seed hex: {}", name, i, test.seed));
        
        // Perform Monte Carlo test according to NIST procedure
        let mut md = seed_bytes.clone();
        
        // Perform the specified number of iterations (typically 100 for SHA-3)
        for j in 0..=test.count {
            // Create a new hash instance
            let mut hasher = H::new();
            
            // Update with the current MD value
            hasher.update(&md).unwrap();
            
            // Generate the next MD value - convert to Vec<u8> to match md's type
            md = hasher.finalize().unwrap().as_ref().to_vec();
        }
        
        // Verify the final result matches the expected value
        let expected = hex::decode(&test.expected).unwrap_or_else(|_| 
            panic!("{} Monte Carlo test {}: Invalid expected hex: {}", name, i, test.expected));
        
        assert_eq!(hex::encode(&md), hex::encode(&expected),
            "{} Monte Carlo test case {} failed.\nExpected: {}\nGot: {}", 
            name, i, test.expected, hex::encode(&md));
    }
}

#[test]
fn test_sha3_nist_monte_vectors() {
    let dir = vectors_dir();
    
    // Path to the Monte Carlo test vector files
    let sha3_224_path = dir.join("SHA3_224Monte.rsp");
    let sha3_256_path = dir.join("SHA3_256Monte.rsp");
    let sha3_384_path = dir.join("SHA3_384Monte.rsp");
    let sha3_512_path = dir.join("SHA3_512Monte.rsp");
    
    // Check if files exist and FAIL if they don't
    for path in [&sha3_224_path, &sha3_256_path, &sha3_384_path, &sha3_512_path] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }
    
    // Run Monte Carlo tests for each SHA-3 variant
    run_sha3_monte_tests::<Sha3_224>(sha3_224_path.to_str().unwrap(), "SHA3-224");
    run_sha3_monte_tests::<Sha3_256>(sha3_256_path.to_str().unwrap(), "SHA3-256");
    run_sha3_monte_tests::<Sha3_384>(sha3_384_path.to_str().unwrap(), "SHA3-384");
    run_sha3_monte_tests::<Sha3_512>(sha3_512_path.to_str().unwrap(), "SHA3-512");
}