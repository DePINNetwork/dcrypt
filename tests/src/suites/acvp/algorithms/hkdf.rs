//! ACVP handlers for HKDF (HMAC-based Key Derivation Function)

use crate::suites::acvp::model::{TestGroup, TestCase};
use crate::suites::acvp::error::{EngineError, Result};
use algorithms::kdf::hkdf::Hkdf;
use algorithms::hash::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use algorithms::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use algorithms::hash::sha1::Sha1;
use algorithms::kdf::KeyDerivationFunction;
use hex;

use super::super::dispatcher::{insert, HandlerFn, DispatchKey};

/// Helper to look for a value in the test case first, then the group defaults.
fn lookup<'a>(case: &'a TestCase, group: &'a TestGroup, names: &[&str]) -> Option<String> {
    for &name in names {
        if let Some(v) = case.inputs.get(name) {
            return Some(v.as_string());
        }
        if let Some(v) = group.defaults.get(name) {
            return Some(v.as_string());
        }
    }
    None
}

/// HKDF Algorithm Functional Test (AFT) handler
pub(crate) fn hkdf_aft(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get inputs using the robust lookup helper with the correct field names from jq analysis.
    let ikm_hex = lookup(case, group, &["inputKeyingMaterial", "ikm", "key"])
        .ok_or(EngineError::MissingField("inputKeyingMaterial"))?;
    
    let salt_hex = lookup(case, group, &["salt", "saltHex"]);
    
    let info_hex = lookup(case, group, &["otherInfo", "info", "infoHex"]);
    
    // Get length - ACVP uses "keyLength" in this suite.
    let length_str = lookup(case, group, &["keyLength", "l", "dkLen", "okmLen"])
        .ok_or(EngineError::MissingField("keyLength"))?;
    // The length in the JSON is in BITS, but the derive function needs BYTES.
    let length_bits = length_str.parse::<usize>()
        .map_err(|_| EngineError::InvalidData(format!("Invalid keyLength: {}", length_str)))?;
    if length_bits % 8 != 0 {
        return Err(EngineError::InvalidData("keyLength must be a multiple of 8".into()));
    }
    let length = length_bits / 8;
    
    // Get expected OKM if provided.
    let expected_okm = lookup(case, group, &["okm", "dkm", "outputKeyingMaterial"]);
    
    // Decode inputs
    let ikm = hex::decode(&ikm_hex)?;
    let salt = salt_hex.as_ref()
        .map(|s| hex::decode(s))
        .transpose()?;
    let info = info_hex.as_ref()
        .map(|i| hex::decode(i))
        .transpose()?;
    
    // Get the HMAC algorithm from group defaults or test case
    let hmac_alg = lookup(case, group, &["hmacAlg"])
        .or_else(|| {
            // Try to extract from the algorithm name as a fallback
            let algo = &group.algorithm;
            if algo.contains("SHA1") || algo.contains("SHA-1") {
                Some("SHA-1".to_string())
            } else if algo.contains("SHA224") || algo.contains("SHA-224") || algo.contains("SHA2-224") {
                Some("SHA2-224".to_string())
            } else if algo.contains("SHA256") || algo.contains("SHA-256") || algo.contains("SHA2-256") {
                Some("SHA2-256".to_string())
            } else if algo.contains("SHA384") || algo.contains("SHA-384") || algo.contains("SHA2-384") {
                Some("SHA2-384".to_string())
            } else if algo.contains("SHA512") || algo.contains("SHA-512") || algo.contains("SHA2-512") {
                Some("SHA2-512".to_string())
            } else {
                None
            }
        })
        .ok_or(EngineError::MissingField("hmacAlg"))?;
    
    // Perform HKDF based on the HMAC algorithm
    let okm_hex = match hmac_alg.as_str() {
        "SHA-1" | "SHA1" => {
            let hkdf = Hkdf::<Sha1>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA-224" | "SHA224" | "SHA2-224" => {
            let hkdf = Hkdf::<Sha224>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA-256" | "SHA256" | "SHA2-256" => {
            let hkdf = Hkdf::<Sha256>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA-384" | "SHA384" | "SHA2-384" => {
            let hkdf = Hkdf::<Sha384>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA-512" | "SHA512" | "SHA2-512" => {
            let hkdf = Hkdf::<Sha512>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA-512/224" | "SHA512/224" | "SHA2-512/224" => {
            let hkdf = Hkdf::<Sha512_224>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA-512/256" | "SHA512/256" | "SHA2-512/256" => {
            let hkdf = Hkdf::<Sha512_256>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA3-224" | "SHA-3-224" => {
            let hkdf = Hkdf::<Sha3_224>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA3-256" | "SHA-3-256" => {
            let hkdf = Hkdf::<Sha3_256>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA3-384" | "SHA-3-384" => {
            let hkdf = Hkdf::<Sha3_384>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        "SHA3-512" | "SHA-3-512" => {
            let hkdf = Hkdf::<Sha3_512>::new();
            let okm = hkdf.derive_key(
                &ikm,
                salt.as_deref(),
                info.as_deref(),
                length
            )?;
            hex::encode(&okm)
        }
        _ => return Err(EngineError::InvalidData(format!("Unsupported HMAC algorithm: {}", hmac_alg))),
    };
    
    // Check result if expected value was provided
    if let Some(expected) = expected_okm {
        if okm_hex != expected {
            return Err(EngineError::Mismatch {
                expected,
                actual: okm_hex,
            });
        }
    } else {
        // Store result for response generation. The field name should be `outputKeyingMaterial`.
        case.outputs.borrow_mut().insert("outputKeyingMaterial".into(), okm_hex);
    }
    
    Ok(())
}

/// Register HKDF handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    // Register AFT handlers for HKDF with various hash functions
    let hkdf_variants = &[
        "HKDF", "HKDF-SHA-1", "HKDF-SHA1",
        "HKDF-SHA-224", "HKDF-SHA224", "HKDF-SHA2-224",
        "HKDF-SHA-256", "HKDF-SHA256", "HKDF-SHA2-256",
        "HKDF-SHA-384", "HKDF-SHA384", "HKDF-SHA2-384",
        "HKDF-SHA-512", "HKDF-SHA512", "HKDF-SHA2-512",
        "HKDF-SHA-512/224", "HKDF-SHA512/224", "HKDF-SHA2-512/224",
        "HKDF-SHA-512/256", "HKDF-SHA512/256", "HKDF-SHA2-512/256",
        "HKDF-SHA3-224", "HKDF-SHA-3-224",
        "HKDF-SHA3-256", "HKDF-SHA-3-256", 
        "HKDF-SHA3-384", "HKDF-SHA-3-384",
        "HKDF-SHA3-512", "HKDF-SHA-3-512",
    ];
    
    for algo in hkdf_variants {
        // AFT tests
        insert(map, algo, "AFT", "AFT", hkdf_aft);
        
        // Some ACVP vectors might not have a specific direction
        insert(map, algo, "", "AFT", hkdf_aft);
    }
}