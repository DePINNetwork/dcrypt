//! ACVP handlers for ML-DSA (Dilithium) operations
//! 
//! This module handles ACVP's non-standard secret key format using a local adapter.

use crate::suites::acvp::model::{TestGroup, TestCase};
use crate::suites::acvp::error::{EngineError, Result};
use dcrypt_sign::pq::dilithium::{
    Dilithium2, Dilithium3, Dilithium5,
    DilithiumPublicKey, DilithiumSecretKey, DilithiumSignatureData,
};
use super::ml_dsa_adapter::AcvpSecretKeyAdapter; // Use the local adapter
use dcrypt_api::Signature;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use hex;

use super::super::dispatcher::{insert, HandlerFn, DispatchKey};

/// Map ACVP parameter set names to Dilithium variants
fn get_parameter_set(group: &TestGroup) -> Result<&'static str> {
    let param_set = group.defaults.get("parameterSet")
        .map(|v| v.as_string())
        .or_else(|| group.params.as_ref()
            .and_then(|p| p.as_object())
            .and_then(|o| o.get("parameterSet"))
            .and_then(|v| v.as_str().map(String::from)))
        .ok_or(EngineError::MissingField("parameterSet"))?;
    
    match param_set.as_str() {
        "ML-DSA-44" => Ok("Dilithium2"),
        "ML-DSA-65" => Ok("Dilithium3"), 
        "ML-DSA-87" => Ok("Dilithium5"),
        other => Err(EngineError::InvalidData(format!("Unknown parameter set: {}", other))),
    }
}

/// ML-DSA Key Generation
pub(crate) fn ml_dsa_keygen(group: &TestGroup, case: &TestCase) -> Result<()> {
    let param_set = get_parameter_set(group)?;
    
    // Check if we have a provided secret key (for deterministic tests)
    if let Some(sk_hex) = case.inputs.get("sk").map(|v| v.as_string()) {
        let sk_bytes = hex::decode(&sk_hex)?;
        
        // Detect format based on size and parse accordingly
        let sk = match (param_set, sk_bytes.len()) {
            // FIPS 204 format sizes (with tr and padding)
            ("Dilithium2", 2560) | ("Dilithium3", 4032) | ("Dilithium5", 4896) => {
                // Already in FIPS 204 format, use directly
                DilithiumSecretKey::from_bytes(&sk_bytes)
                    .map_err(|e| EngineError::Crypto(e.to_string()))?
            }
            // ACVP format sizes (without tr and padding)
            ("Dilithium2", 2496) | ("Dilithium3", 3968) | ("Dilithium5", 4832) => {
                // Parse ACVP format and convert to FIPS 204
                AcvpSecretKeyAdapter::from_acvp_bytes(&sk_bytes, param_set)
                    .map_err(|e| EngineError::Crypto(e.to_string()))?
            }
            _ => {
                return Err(EngineError::InvalidData(format!(
                    "Unexpected secret key size {} for {}", sk_bytes.len(), param_set
                )));
            }
        };
        
        // Extract public key
        let pk = sk.public_key()
            .map_err(|e| EngineError::Crypto(e.to_string()))?;
        
        // Output in the same format as input
        let sk_output = match (param_set, sk_bytes.len()) {
            // If input was FIPS 204 format, output FIPS 204 format
            ("Dilithium2", 2560) | ("Dilithium3", 4032) | ("Dilithium5", 4896) => {
                sk.to_bytes().to_vec()
            }
            // If input was ACVP format, output ACVP format
            _ => {
                AcvpSecretKeyAdapter::to_acvp_bytes(&sk, param_set)
                    .map_err(|e| EngineError::Crypto(e.to_string()))?
            }
        };
        
        case.outputs.borrow_mut().insert("pk".into(), hex::encode(pk.to_bytes()));
        case.outputs.borrow_mut().insert("sk".into(), hex::encode(sk_output));
    } else {
        // Generate new keypair
        let mut rng = if let Some(seed_hex) = case.inputs.get("seed").map(|v| v.as_string()) {
            let seed_bytes = hex::decode(&seed_hex)?;
            let mut seed = [0u8; 32];
            let len = seed_bytes.len().min(32);
            seed[..len].copy_from_slice(&seed_bytes[..len]);
            ChaCha20Rng::from_seed(seed)
        } else {
            ChaCha20Rng::from_entropy()
        };
        
        // Generate keypair based on parameter set
        let (pk, sk) = match param_set {
            "Dilithium2" => {
                let (pk, sk) = Dilithium2::keypair(&mut rng)
                    .map_err(|e| EngineError::Crypto(format!("Dilithium2 keypair generation failed: {:?}", e)))?;
                (pk, sk)
            }
            "Dilithium3" => {
                let (pk, sk) = Dilithium3::keypair(&mut rng)
                    .map_err(|e| EngineError::Crypto(format!("Dilithium3 keypair generation failed: {:?}", e)))?;
                (pk, sk)
            }
            "Dilithium5" => {
                let (pk, sk) = Dilithium5::keypair(&mut rng)
                    .map_err(|e| EngineError::Crypto(format!("Dilithium5 keypair generation failed: {:?}", e)))?;
                (pk, sk)
            }
            _ => unreachable!(),
        };
        
        // Convert to ACVP format for response
        let acvp_sk = AcvpSecretKeyAdapter::to_acvp_bytes(&sk, param_set)
            .map_err(|e| EngineError::Crypto(e.to_string()))?;
        
        // Store outputs in ACVP format
        case.outputs.borrow_mut().insert("pk".into(), hex::encode(pk.to_bytes()));
        case.outputs.borrow_mut().insert("sk".into(), hex::encode(acvp_sk));
    }
    
    Ok(())
}

/// ML-DSA Signature Generation
pub(crate) fn ml_dsa_siggen(group: &TestGroup, case: &TestCase) -> Result<()> {
    let param_set = get_parameter_set(group)?;
    
    // Get message - handle both "message" and "msg" field names, or empty message
    let msg_bytes = case.inputs.get("message")
        .or_else(|| case.inputs.get("msg"))
        .map(|v| hex::decode(&v.as_string()))
        .transpose()?
        .unwrap_or_else(|| {
            // Some ACVP tests may have empty/missing message
            println!("Note: Using empty message for test case");
            Vec::new()
        });
    
    // Check if we have a provided secret key
    if let Some(sk_hex) = case.inputs.get("sk").map(|v| v.as_string()) {
        let sk_bytes = hex::decode(&sk_hex)?;
        
        // Detect format based on size and parse accordingly
        let sk = match (param_set, sk_bytes.len()) {
            // FIPS 204 format sizes (with tr and padding)
            ("Dilithium2", 2560) | ("Dilithium3", 4032) | ("Dilithium5", 4896) => {
                // Already in FIPS 204 format, use directly
                DilithiumSecretKey::from_bytes(&sk_bytes)
                    .map_err(|e| EngineError::Crypto(e.to_string()))?
            }
            // ACVP format sizes (without tr and padding)
            ("Dilithium2", 2496) | ("Dilithium3", 3968) | ("Dilithium5", 4832) => {
                // Parse ACVP format and convert to FIPS 204
                AcvpSecretKeyAdapter::from_acvp_bytes(&sk_bytes, param_set)
                    .map_err(|e| EngineError::Crypto(e.to_string()))?
            }
            _ => {
                return Err(EngineError::InvalidData(format!(
                    "Unexpected secret key size {} for {}", sk_bytes.len(), param_set
                )));
            }
        };
        
        // Sign using standard API
        let sig = match param_set {
            "Dilithium2" => Dilithium2::sign(&msg_bytes, &sk)
                .map_err(|e| EngineError::Crypto(format!("Signing failed: {:?}", e)))?,
            "Dilithium3" => Dilithium3::sign(&msg_bytes, &sk)
                .map_err(|e| EngineError::Crypto(format!("Signing failed: {:?}", e)))?,
            "Dilithium5" => Dilithium5::sign(&msg_bytes, &sk)
                .map_err(|e| EngineError::Crypto(format!("Signing failed: {:?}", e)))?,
            _ => unreachable!(),
        };
        
        // Also extract the public key for the response
        let pk = sk.public_key()
            .map_err(|e| EngineError::Crypto(e.to_string()))?;
        
        // Output in the same format as input
        let sk_output = match (param_set, sk_bytes.len()) {
            // If input was FIPS 204 format, output FIPS 204 format
            ("Dilithium2", 2560) | ("Dilithium3", 4032) | ("Dilithium5", 4896) => {
                sk.to_bytes().to_vec()
            }
            // If input was ACVP format, output ACVP format
            _ => {
                AcvpSecretKeyAdapter::to_acvp_bytes(&sk, param_set)
                    .map_err(|e| EngineError::Crypto(e.to_string()))?
            }
        };
        
        case.outputs.borrow_mut().insert("pk".into(), hex::encode(pk.to_bytes()));
        case.outputs.borrow_mut().insert("sk".into(), hex::encode(sk_output));
        case.outputs.borrow_mut().insert("signature".into(), hex::encode(sig.to_bytes()));
    } else {
        // No secret key provided - generate a fresh keypair
        let mut rng = ChaCha20Rng::from_entropy();
        
        let (pk, sk, sig) = match param_set {
            "Dilithium2" => {
                let (pk, sk) = Dilithium2::keypair(&mut rng)
                    .map_err(|e| EngineError::Crypto(format!("Keypair generation failed: {:?}", e)))?;
                let sig = Dilithium2::sign(&msg_bytes, &sk)
                    .map_err(|e| EngineError::Crypto(format!("Signing failed: {:?}", e)))?;
                (pk, sk, sig)
            }
            "Dilithium3" => {
                let (pk, sk) = Dilithium3::keypair(&mut rng)
                    .map_err(|e| EngineError::Crypto(format!("Keypair generation failed: {:?}", e)))?;
                let sig = Dilithium3::sign(&msg_bytes, &sk)
                    .map_err(|e| EngineError::Crypto(format!("Signing failed: {:?}", e)))?;
                (pk, sk, sig)
            }
            "Dilithium5" => {
                let (pk, sk) = Dilithium5::keypair(&mut rng)
                    .map_err(|e| EngineError::Crypto(format!("Keypair generation failed: {:?}", e)))?;
                let sig = Dilithium5::sign(&msg_bytes, &sk)
                    .map_err(|e| EngineError::Crypto(format!("Signing failed: {:?}", e)))?;
                (pk, sk, sig)
            }
            _ => unreachable!(),
        };
        
        // Convert SK to ACVP format for output
        let acvp_sk = AcvpSecretKeyAdapter::to_acvp_bytes(&sk, param_set)
            .map_err(|e| EngineError::Crypto(e.to_string()))?;
        
        case.outputs.borrow_mut().insert("pk".into(), hex::encode(pk.to_bytes()));
        case.outputs.borrow_mut().insert("sk".into(), hex::encode(acvp_sk));
        case.outputs.borrow_mut().insert("signature".into(), hex::encode(sig.to_bytes()));
    }
    
    Ok(())
}

/// ML-DSA Signature Verification
pub(crate) fn ml_dsa_sigver(group: &TestGroup, case: &TestCase) -> Result<()> {
    let param_set = get_parameter_set(group)?;
    
    // Get inputs - handle missing message gracefully
    let msg_bytes = case.inputs.get("message")
        .or_else(|| case.inputs.get("msg"))
        .map(|v| hex::decode(&v.as_string()))
        .transpose()?
        .unwrap_or_else(|| {
            // Empty message for missing field
            println!("Note: Using empty message for verification test");
            Vec::new()
        });
    
    let pk_hex = case.inputs.get("pk")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("pk"))?;
    let sig_hex = case.inputs.get("signature")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("signature"))?;
    
    let pk_bytes = hex::decode(&pk_hex)?;
    let sig_bytes = hex::decode(&sig_hex)?;
    
    // Try to create typed wrappers with full validation
    let pk = match DilithiumPublicKey::from_bytes(&pk_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            // Invalid public key - test should fail
            case.outputs.borrow_mut().insert("testPassed".into(), "false".into());
            case.outputs.borrow_mut().insert("reason".into(), "invalid public key format".into());
            return Ok(());
        }
    };
    
    let sig = match DilithiumSignatureData::from_bytes(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            // Invalid signature format - test should fail
            case.outputs.borrow_mut().insert("testPassed".into(), "false".into());
            case.outputs.borrow_mut().insert("reason".into(), "invalid signature format".into());
            return Ok(());
        }
    };
    
    // Verify signature
    let result = match param_set {
        "Dilithium2" => Dilithium2::verify(&msg_bytes, &sig, &pk).is_ok(),
        "Dilithium3" => Dilithium3::verify(&msg_bytes, &sig, &pk).is_ok(),
        "Dilithium5" => Dilithium5::verify(&msg_bytes, &sig, &pk).is_ok(),
        _ => unreachable!(),
    };
    
    case.outputs.borrow_mut().insert("testPassed".into(), result.to_string());
    Ok(())
}

/// Register ML-DSA handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    // Key generation
    insert(map, "ML-DSA-keyGen", "AFT", "AFT", ml_dsa_keygen);
    
    // Signature generation
    insert(map, "ML-DSA-sigGen", "AFT", "AFT", ml_dsa_siggen);
    
    // Signature verification
    insert(map, "ML-DSA-sigVer", "AFT", "AFT", ml_dsa_sigver);
}