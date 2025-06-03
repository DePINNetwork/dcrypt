//! ACVP handlers for AES-CTR mode

use crate::suites::acvp::model::{TestGroup, TestCase};
use crate::suites::acvp::error::{EngineError, Result};
use algorithms::block::aes::{Aes128, Aes192, Aes256};
use algorithms::block::modes::ctr::{Ctr, CounterPosition};
use algorithms::block::BlockCipher;
use algorithms::types::{Nonce, SecretBytes};
use arrayref::array_ref;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use rand::{RngCore, thread_rng};

use super::super::dispatcher::{insert, HandlerFn, DispatchKey};

// Small utility: look in the case, then in the group defaults
fn lookup<'a>(case: &'a TestCase,
              group: &'a TestGroup,
              names: &[&str]) -> Option<String>
{
    for &n in names {
        if let Some(v) = case.inputs.get(n) {
            return Some(v.as_string());
        }
        if let Some(v) = group.defaults.get(n) {
            return Some(v.as_string());
        }
    }
    None
}

/// Standard AES-CTR AFT encrypt
pub(crate) fn aes_ctr_encrypt(group: &TestGroup, case: &TestCase) -> Result<()> {
    aes_ctr_process(group, case, true)
}

/// Standard AES-CTR AFT decrypt
pub(crate) fn aes_ctr_decrypt(group: &TestGroup, case: &TestCase) -> Result<()> {
    // In CTR mode, encryption and decryption are the same operation
    aes_ctr_process(group, case, false)
}

/// Common processing for CTR mode
fn aes_ctr_process(group: &TestGroup, case: &TestCase, is_encrypt: bool) -> Result<()> {
    // Get inputs - ACVP uses short field names
    let key_hex = case.inputs.get("key")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("key"))?;
    
    // For CTR mode, the input/output field names depend on direction
    let (input_field, output_field) = if is_encrypt {
        ("pt", "ct")
    } else {
        ("ct", "pt")
    };
    
    let input_hex = case.inputs.get(input_field)
        .or_else(|| case.inputs.get(if is_encrypt { "plainText" } else { "cipherText" }))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField(input_field))?;
    
    // Expected output is OPTIONAL
    let expected_hex = case.inputs.get(output_field)
        .or_else(|| case.inputs.get(if is_encrypt { "cipherText" } else { "plainText" }))
        .map(|v| v.as_string());
    
    // Decode hex values
    let mut key_bytes = hex::decode(&key_hex)?;
    let input = hex::decode(&input_hex)?;
    
    // Handle IV/counter - for encrypt, it might need to be generated
    let iv_bytes = if let Some(iv_hex) = lookup(case, group, &["iv", "ctr", "nonce", "counter"]) {
        // IV was provided
        hex::decode(&iv_hex)?
    } else if is_encrypt {
        // No IV provided for encrypt - generate one
        let mut iv = [0u8; 16];
        thread_rng().fill_bytes(&mut iv);
        
        // Store the generated IV in outputs for the response
        case.outputs.borrow_mut().insert("iv".into(), hex::encode(&iv));
        
        iv.to_vec()
    } else {
        // Decrypt requires an IV
        return Err(EngineError::MissingField("iv"));
    };
    
    // ACVP CTR test vectors use the full block as the initial counter value
    if iv_bytes.len() != 16 {
        return Err(EngineError::InvalidData(
            format!("CTR mode requires 16-byte IV/counter, got {} bytes", iv_bytes.len())
        ));
    }
    
    // Process based on key size
    let result = match key_bytes.len() {
        16 => {
            let key = SecretBytes::<16>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes128::new(&key);
            process_ctr_with_full_counter(cipher, &iv_bytes, &input)?
        }
        24 => {
            let key = SecretBytes::<24>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes192::new(&key);
            process_ctr_with_full_counter(cipher, &iv_bytes, &input)?
        }
        32 => {
            let key = SecretBytes::<32>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes256::new(&key);
            process_ctr_with_full_counter(cipher, &iv_bytes, &input)?
        }
        n => return Err(EngineError::KeySize(n)),
    };
    
    // Zeroize sensitive data
    key_bytes.zeroize();
    
    // Check result if expected value was provided
    if let Some(exp_hex) = expected_hex {
        let expected = hex::decode(&exp_hex)?;
        // Use constant-time comparison
        if result.ct_eq(&expected).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(EngineError::Mismatch {
                expected: exp_hex,
                actual: hex::encode(&result),
            })
        }
    } else {
        // Store result for response generation
        case.outputs.borrow_mut().insert(output_field.into(), hex::encode(&result));
        Ok(())
    }
}

/// Process CTR mode with a full 16-byte counter block (ACVP style)
fn process_ctr_with_full_counter<B: BlockCipher + Clone + zeroize::Zeroize>(
    cipher: B,
    counter_block: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    // ACVP provides the full counter block in the IV field
    // We need to set up CTR mode to use it properly
    
    // Use the first 12 bytes as nonce, last 4 as counter
    let nonce_bytes = &counter_block[0..12];
    let initial_counter = u32::from_be_bytes([
        counter_block[12],
        counter_block[13],
        counter_block[14],
        counter_block[15],
    ]);
    
    // Create nonce
    let nonce = Nonce::<12>::new(*array_ref![nonce_bytes, 0, 12]);
    
    // Create CTR instance with standard configuration (4-byte counter at end)
    let mut ctr = Ctr::with_counter_params(
        cipher,
        &nonce,
        CounterPosition::Postfix,
        4
    )?;
    
    // Set the initial counter value
    ctr.set_counter(initial_counter);
    
    // Process the data
    Ok(ctr.encrypt(data)?)
}

/// AES-CTR MCT encryption
pub(crate) fn aes_ctr_mct_encrypt(group: &TestGroup, case: &TestCase) -> Result<()> {
    aes_ctr_mct_process(group, case, true)
}

/// AES-CTR MCT decryption
pub(crate) fn aes_ctr_mct_decrypt(group: &TestGroup, case: &TestCase) -> Result<()> {
    aes_ctr_mct_process(group, case, false)
}

/// Common MCT processing for CTR mode
fn aes_ctr_mct_process(group: &TestGroup, case: &TestCase, is_encrypt: bool) -> Result<()> {
    // Parse inputs
    let mut key = hex::decode(
        &case.inputs.get("key")
            .map(|v| v.as_string())
            .ok_or(EngineError::MissingField("key"))?
    )?;
    
    // ACVP may call the counter block iv, ctr, or nonce
    let mut iv = hex::decode(
        &lookup(case, group, &["iv", "ctr", "nonce", "counter"])
            .ok_or(EngineError::MissingField("iv"))?
    )?;
    
    // Initial data
    let (input_field, output_field) = if is_encrypt {
        ("pt", "ct")
    } else {
        ("ct", "pt")
    };
    
    let mut data = hex::decode(
        &case.inputs.get(input_field)
            .map(|v| v.as_string())
            .ok_or(EngineError::MissingField(input_field))?
    )?;
    
    // Ensure IV is 16 bytes
    if iv.len() != 16 {
        return Err(EngineError::InvalidData(
            format!("CTR MCT requires 16-byte IV, got {} bytes", iv.len())
        ));
    }
    
    // Build cipher once based on key size
    enum CipherVariant {
        Aes128(Aes128),
        Aes192(Aes192),
        Aes256(Aes256),
    }
    
    let cipher = match key.len() {
        16 => {
            let key_array = array_ref![key, 0, 16];
            let secret_key = SecretBytes::<16>::new(*key_array);
            CipherVariant::Aes128(Aes128::new(&secret_key))
        }
        24 => {
            let key_array = array_ref![key, 0, 24];
            let secret_key = SecretBytes::<24>::new(*key_array);
            CipherVariant::Aes192(Aes192::new(&secret_key))
        }
        32 => {
            let key_array = array_ref![key, 0, 32];
            let secret_key = SecretBytes::<32>::new(*key_array);
            CipherVariant::Aes256(Aes256::new(&secret_key))
        }
        n => return Err(EngineError::KeySize(n)),
    };
    
    // Monte Carlo loop - 1000 iterations
    for _ in 0..1000 {
        // Process the current data
        let result = match &cipher {
            CipherVariant::Aes128(c) => {
                process_ctr_with_full_counter(c.clone(), &iv, &data)?
            }
            CipherVariant::Aes192(c) => {
                process_ctr_with_full_counter(c.clone(), &iv, &data)?
            }
            CipherVariant::Aes256(c) => {
                process_ctr_with_full_counter(c.clone(), &iv, &data)?
            }
        };
        
        // For CTR MCT, the IV is incremented by 1 for each iteration
        // Increment the counter portion (last 4 bytes) as a big-endian integer
        let mut counter = u32::from_be_bytes([iv[12], iv[13], iv[14], iv[15]]);
        counter = counter.wrapping_add(1);
        iv[12..16].copy_from_slice(&counter.to_be_bytes());
        
        // Update data for next iteration
        data = result;
    }
    
    // Zeroize sensitive data
    key.zeroize();
    iv.zeroize();
    
    // Check or store result
    if let Some(expected_hex) = case.inputs.get(output_field).map(|v| v.as_string()) {
        let result_hex = hex::encode(&data);
        if result_hex == expected_hex {
            Ok(())
        } else {
            Err(EngineError::Mismatch {
                expected: expected_hex,
                actual: result_hex,
            })
        }
    } else {
        case.outputs.borrow_mut().insert(output_field.into(), hex::encode(&data));
        Ok(())
    }
}

/// Register AES-CTR handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    insert(map, "AES-CTR", "encrypt", "AFT", aes_ctr_encrypt);
    insert(map, "AES-CTR", "decrypt", "AFT", aes_ctr_decrypt);
    insert(map, "AES-CTR", "encrypt", "MCT", aes_ctr_mct_encrypt);
    insert(map, "AES-CTR", "decrypt", "MCT", aes_ctr_mct_decrypt);
}