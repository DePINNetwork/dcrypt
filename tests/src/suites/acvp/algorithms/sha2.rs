//! ACVP handlers for SHA-2 hash functions

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{FlexValue, TestCase, TestGroup};
use dcrypt_algorithms::hash::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use dcrypt_algorithms::hash::HashFunction;
use hex;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

/// SHA-2 Algorithm Family Test (AFT) handler
/// Handles SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256
pub(crate) fn sha2_aft(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get the message to hash - ACVP uses "msg" field
    let msg_hex = case
        .inputs
        .get("msg")
        .or_else(|| case.inputs.get("message"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("msg"))?;

    // Decode the message from hex
    let msg_bytes = hex::decode(&msg_hex)?;

    // Get expected digest if provided (for validation)
    let expected_md = case
        .inputs
        .get("md")
        .or_else(|| case.inputs.get("digest"))
        .map(|v| v.as_string());

    // Determine which SHA-2 variant to use based on the algorithm name
    let algorithm = &group.algorithm;

    let digest_hex = match algorithm.as_str() {
        "SHA2-224" | "SHA-224" => {
            let digest = Sha224::digest(&msg_bytes)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-256" | "SHA-256" => {
            let digest = Sha256::digest(&msg_bytes)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-384" | "SHA-384" => {
            let digest = Sha384::digest(&msg_bytes)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-512" | "SHA-512" => {
            let digest = Sha512::digest(&msg_bytes)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-512/224" | "SHA2-512-224" | "SHA-512/224" => {
            let digest = Sha512_224::digest(&msg_bytes)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-512/256" | "SHA2-512-256" | "SHA-512/256" => {
            let digest = Sha512_256::digest(&msg_bytes)?;
            hex::encode(digest.as_ref())
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHA-2 variant: {}",
                algorithm
            )))
        }
    };

    // Check result if expected value was provided
    if let Some(expected) = expected_md {
        if digest_hex != expected {
            return Err(EngineError::Mismatch {
                expected,
                actual: digest_hex,
            });
        }
    } else {
        // Store result for response generation
        case.outputs.borrow_mut().insert("md".into(), digest_hex);
    }

    Ok(())
}

/// SHA-2 Monte Carlo Test (MCT) handler
pub(crate) fn sha2_mct(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get the initial seed
    let seed_hex = case
        .inputs
        .get("seed")
        .or_else(|| case.inputs.get("msg"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("seed"))?;

    let seed_bytes = hex::decode(&seed_hex)?;

    // Get expected final digest if provided
    let expected_md = case.inputs.get("md").map(|v| v.as_string());

    // Determine which SHA-2 variant to use
    let algorithm = &group.algorithm;

    // SHA-2 Monte Carlo test procedure:
    // MD[0] = Seed
    // MD[1] = SHA(MD[0])
    // MD[2] = SHA(MD[1])
    // For j = 3 to 999:
    //   MD[j] = SHA(MD[j-3] || MD[j-2] || MD[j-1])
    // Output MD[999]

    let final_digest = match algorithm.as_str() {
        "SHA2-224" | "SHA-224" => sha2_mct_inner::<Sha224>(&seed_bytes, 1000)?,
        "SHA2-256" | "SHA-256" => sha2_mct_inner::<Sha256>(&seed_bytes, 1000)?,
        "SHA2-384" | "SHA-384" => sha2_mct_inner::<Sha384>(&seed_bytes, 1000)?,
        "SHA2-512" | "SHA-512" => sha2_mct_inner::<Sha512>(&seed_bytes, 1000)?,
        "SHA2-512/224" | "SHA2-512-224" | "SHA-512/224" => {
            sha2_mct_inner::<Sha512_224>(&seed_bytes, 1000)?
        }
        "SHA2-512/256" | "SHA2-512-256" | "SHA-512/256" => {
            sha2_mct_inner::<Sha512_256>(&seed_bytes, 1000)?
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHA-2 variant: {}",
                algorithm
            )))
        }
    };

    let digest_hex = hex::encode(&final_digest);

    // Check result if expected value was provided
    if let Some(expected) = expected_md {
        if digest_hex != expected {
            return Err(EngineError::Mismatch {
                expected,
                actual: digest_hex,
            });
        }
    } else {
        // Store result for response generation
        case.outputs.borrow_mut().insert("md".into(), digest_hex);
    }

    Ok(())
}

/// Inner function for Monte Carlo Test implementation
fn sha2_mct_inner<H: HashFunction>(seed: &[u8], iterations: usize) -> Result<Vec<u8>>
where
    H::Output: AsRef<[u8]>,
{
    // Initialize MD array
    let mut md = Vec::new();

    // MD[0] = Seed
    md.push(seed.to_vec());

    // MD[1] = SHA(MD[0])
    let digest1 = H::digest(&md[0])?;
    md.push(digest1.as_ref().to_vec());

    // MD[2] = SHA(MD[1])
    let digest2 = H::digest(&md[1])?;
    md.push(digest2.as_ref().to_vec());

    // For j = 3 to iterations-1:
    for _j in 3..iterations {
        // MD[j] = SHA(MD[j-3] || MD[j-2] || MD[j-1])
        let mut input = Vec::new();
        input.extend_from_slice(&md[md.len() - 3]);
        input.extend_from_slice(&md[md.len() - 2]);
        input.extend_from_slice(&md[md.len() - 1]);

        let digest = H::digest(&input)?;
        md.push(digest.as_ref().to_vec());

        // To save memory, we can remove old entries we don't need anymore
        if md.len() > 3 {
            md.remove(0);
        }
    }

    // Return the last digest
    Ok(md.last().unwrap().clone())
}

/// Large Data Test (LDT) handler for SHA-2
/// Tests hashing of very large messages
pub(crate) fn sha2_ldt(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Check if this test case uses the largeMsg structure
    if let Some(large_msg_value) = case.inputs.get("largeMsg") {
        // Handle the largeMsg structure
        return handle_large_msg_test(group, case, large_msg_value);
    }

    // Original logic for regular LDT tests

    // Get expansion technique first to determine how to handle the message
    let expansion_technique = case
        .inputs
        .get("expansionTechnique")
        .map(|v| v.as_string().to_lowercase())
        .unwrap_or_else(|| "repeating".to_string());

    // Try to get content length from various possible field names
    let content_len_bits_opt = case
        .inputs
        .get("contentLength")
        .or_else(|| case.inputs.get("contentLen"))
        .or_else(|| case.inputs.get("len"))
        .or_else(|| case.inputs.get("msgLen"))
        .map(|v| v.as_string())
        .and_then(|s| s.parse::<usize>().ok());

    // Helper that converts bits→bytes and validates the multiple-of-8 rule
    let bits_to_bytes = |bits: usize| -> Result<usize> {
        if bits % 8 == 0 {
            Ok(bits / 8)
        } else {
            Err(EngineError::InvalidData(
                "Content length must be multiple of 8 bits".into(),
            ))
        }
    };

    // Generate the full message based on expansion technique
    let full_message = match expansion_technique.as_str() {
        "repeating" => {
            let content_len_bytes = bits_to_bytes(
                content_len_bits_opt.ok_or(EngineError::MissingField("contentLength/len"))?,
            )?;

            let content_hex = case
                .inputs
                .get("content")
                .or_else(|| case.inputs.get("msg"))
                .or_else(|| case.inputs.get("message"))
                .map(|v| v.as_string())
                .unwrap_or_else(|| "".to_string());

            let content_bytes = if content_hex.is_empty() {
                vec![]
            } else {
                hex::decode(&content_hex)?
            };

            build_repeating(&content_bytes, content_len_bytes)?
        }
        "counter" => {
            let content_len_bytes = bits_to_bytes(
                content_len_bits_opt.ok_or(EngineError::MissingField("contentLength/len"))?,
            )?;

            let content_hex = case
                .inputs
                .get("content")
                .or_else(|| case.inputs.get("msg"))
                .or_else(|| case.inputs.get("message"))
                .map(|v| v.as_string())
                .unwrap_or_else(|| "".to_string());

            let prefix = if content_hex.is_empty() {
                vec![]
            } else {
                hex::decode(&content_hex)?
            };

            build_counter(&prefix, content_len_bytes, true)?
        }
        "incrementingcounter" => {
            let content_len_bytes = bits_to_bytes(
                content_len_bits_opt.ok_or(EngineError::MissingField("contentLength/len"))?,
            )?;

            let content_hex = case
                .inputs
                .get("content")
                .or_else(|| case.inputs.get("msg"))
                .or_else(|| case.inputs.get("message"))
                .map(|v| v.as_string())
                .unwrap_or_else(|| "".to_string());

            let prefix = if content_hex.is_empty() {
                vec![]
            } else {
                hex::decode(&content_hex)?
            };

            build_counter(&prefix, content_len_bytes, false)?
        }
        "random" => {
            let message_hex = case
                .inputs
                .get("MESSAGE")
                .or_else(|| case.inputs.get("message"))
                .or_else(|| case.inputs.get("msg"))
                .map(|v| v.as_string())
                .ok_or(EngineError::MissingField("MESSAGE for random expansion"))?;

            let msg = hex::decode(&message_hex)?;

            if let Some(bits) = content_len_bits_opt {
                let expected = bits_to_bytes(bits)?;
                if expected != msg.len() {
                    return Err(EngineError::Mismatch {
                        expected: format!("{} bytes", expected),
                        actual: format!("{} bytes", msg.len()),
                    });
                }
            }
            msg
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported expansion technique: {}",
                expansion_technique
            )))
        }
    };

    // Hash the message and check results
    hash_and_check_result(group, case, &full_message)
}

/// Handle test cases with the largeMsg structure
fn handle_large_msg_test(
    group: &TestGroup,
    case: &TestCase,
    large_msg_value: &FlexValue,
) -> Result<()> {
    // Parse the largeMsg object
    let large_msg = match large_msg_value {
        FlexValue::Object(map) => map,
        _ => {
            return Err(EngineError::InvalidData(
                "largeMsg must be an object".into(),
            ))
        }
    };

    // Extract fields from largeMsg
    let content_hex = large_msg
        .get("content")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("largeMsg.content"))?;

    // Get fullLength - try both as string and number
    let full_length_bits = large_msg
        .get("fullLength")
        .map(|v| match v {
            FlexValue::String(s) => s.parse::<usize>().ok(),
            FlexValue::Number(n) => n.as_u64().map(|x| x as usize),
            _ => None,
        })
        .flatten()
        .ok_or(EngineError::MissingField("largeMsg.fullLength"))?;

    let expansion_technique = large_msg
        .get("expansionTechnique")
        .map(|v| v.as_string())
        .unwrap_or_else(|| "repeating".to_string());

    // Convert bits to bytes
    if full_length_bits % 8 != 0 {
        return Err(EngineError::InvalidData(
            "fullLength must be multiple of 8 bits".into(),
        ));
    }
    let full_length_bytes = full_length_bits / 8;

    // Decode the content pattern
    let content_bytes = hex::decode(&content_hex)?;

    // For very large messages, check if we can handle them
    const MAX_SIZE: usize = 100 * 1024 * 1024; // 100 MB limit

    if full_length_bytes > MAX_SIZE {
        // Skip tests that are too large
        eprintln!(
            "Skipping LDT test {} - message size {} MB exceeds {} MB limit",
            case.test_id,
            full_length_bytes / (1024 * 1024),
            MAX_SIZE / (1024 * 1024)
        );

        // If there's an expected digest, we need to return an error
        if case.inputs.contains_key("md") {
            return Err(EngineError::InvalidData(format!(
                "Cannot process {} MB message in memory",
                full_length_bytes / (1024 * 1024)
            )));
        }

        // Otherwise, mark as skipped
        case.outputs
            .borrow_mut()
            .insert("testPassed".into(), "false".into());
        case.outputs.borrow_mut().insert(
            "reason".into(),
            format!(
                "Message too large: {} MB",
                full_length_bytes / (1024 * 1024)
            ),
        );

        return Ok(());
    }

    // Generate the full message
    let full_message = match expansion_technique.as_str() {
        "repeating" => build_repeating(&content_bytes, full_length_bytes)?,
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported expansion technique in largeMsg: {}",
                expansion_technique
            )))
        }
    };

    // Hash the message and check results
    hash_and_check_result(group, case, &full_message)
}

/// Common function to hash a message and check the result
fn hash_and_check_result(group: &TestGroup, case: &TestCase, message: &[u8]) -> Result<()> {
    // Get expected digest if provided
    let expected_md = case.inputs.get("md").map(|v| v.as_string());

    // Determine which SHA-2 variant to use
    let algorithm = &group.algorithm;

    let digest_hex = match algorithm.as_str() {
        "SHA2-224" | "SHA-224" => {
            let digest = Sha224::digest(message)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-256" | "SHA-256" => {
            let digest = Sha256::digest(message)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-384" | "SHA-384" => {
            let digest = Sha384::digest(message)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-512" | "SHA-512" => {
            let digest = Sha512::digest(message)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-512/224" | "SHA2-512-224" | "SHA-512/224" => {
            let digest = Sha512_224::digest(message)?;
            hex::encode(digest.as_ref())
        }
        "SHA2-512/256" | "SHA2-512-256" | "SHA-512/256" => {
            let digest = Sha512_256::digest(message)?;
            hex::encode(digest.as_ref())
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHA-2 variant: {}",
                algorithm
            )))
        }
    };

    // Check result if expected value was provided
    if let Some(expected) = expected_md {
        if digest_hex != expected {
            return Err(EngineError::Mismatch {
                expected,
                actual: digest_hex,
            });
        }
    } else {
        // Store result for response generation
        case.outputs.borrow_mut().insert("md".into(), digest_hex);
    }

    Ok(())
}

/// Build a message by repeating a pattern to reach target length
fn build_repeating(pattern: &[u8], target_len: usize) -> Result<Vec<u8>> {
    if target_len == 0 {
        return Ok(vec![]);
    }

    if pattern.is_empty() {
        // Empty pattern but non-zero length requested - error
        return Err(EngineError::InvalidData(
            "Non-zero length requested but pattern is empty".into(),
        ));
    }

    let mut message = Vec::with_capacity(target_len);
    while message.len() < target_len {
        let remaining = target_len - message.len();
        if remaining >= pattern.len() {
            message.extend_from_slice(pattern);
        } else {
            message.extend_from_slice(&pattern[..remaining]);
        }
    }

    Ok(message)
}

/// Build a message with prefix followed by counter blocks
/// If big_endian is true, use big-endian counters; otherwise little-endian
fn build_counter(prefix: &[u8], target_len: usize, big_endian: bool) -> Result<Vec<u8>> {
    if target_len == 0 {
        return Ok(vec![]);
    }

    let mut message = Vec::with_capacity(target_len);

    // Start with the prefix (which may be empty)
    message.extend_from_slice(prefix);

    // Add counter blocks until we reach the target length
    let mut counter: u32 = 0;
    while message.len() < target_len {
        let counter_bytes = if big_endian {
            counter.to_be_bytes()
        } else {
            counter.to_le_bytes()
        };

        let remaining = target_len - message.len();
        if remaining >= 4 {
            message.extend_from_slice(&counter_bytes);
        } else {
            // Final partial block
            message.extend_from_slice(&counter_bytes[..remaining]);
        }

        counter = counter.wrapping_add(1);
    }

    Ok(message)
}

/// Register SHA-2 handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    // Register AFT handlers for all SHA-2 variants
    // Include all possible algorithm name variations that ACVP might use
    for algo in &[
        "SHA2-224",
        "SHA-224",
        "SHA2-256",
        "SHA-256",
        "SHA2-384",
        "SHA-384",
        "SHA2-512",
        "SHA-512",
        "SHA2-512-224",
        "SHA-512/224",
        "SHA2-512/224", // Added SHA2-512/224
        "SHA2-512-256",
        "SHA-512/256",
        "SHA2-512/256",
    ]
    // Added SHA2-512/256
    {
        insert(map, algo, "AFT", "AFT", sha2_aft);
    }

    // Register MCT handlers for all SHA-2 variants
    for algo in &[
        "SHA2-224",
        "SHA-224",
        "SHA2-256",
        "SHA-256",
        "SHA2-384",
        "SHA-384",
        "SHA2-512",
        "SHA-512",
        "SHA2-512-224",
        "SHA-512/224",
        "SHA2-512/224", // Added SHA2-512/224
        "SHA2-512-256",
        "SHA-512/256",
        "SHA2-512/256",
    ]
    // Added SHA2-512/256
    {
        insert(map, algo, "MCT", "MCT", sha2_mct);
    }

    // Register LDT handlers for all SHA-2 variants
    for algo in &[
        "SHA2-224",
        "SHA-224",
        "SHA2-256",
        "SHA-256",
        "SHA2-384",
        "SHA-384",
        "SHA2-512",
        "SHA-512",
        "SHA2-512-224",
        "SHA-512/224",
        "SHA2-512/224", // Added SHA2-512/224
        "SHA2-512-256",
        "SHA-512/256",
        "SHA2-512/256",
    ]
    // Added SHA2-512/256
    {
        insert(map, algo, "LDT", "LDT", sha2_ldt);
    }
}
