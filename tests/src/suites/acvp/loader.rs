//! Loads ACVP test vectors from JSON files.

use crate::suites::acvp::model::{SuiteMeta, TestSuite, FlexValue};
use once_cell::sync::Lazy;
use std::{fs, path::{Path, PathBuf}};
use std::collections::HashMap;

/// ----------------------------------------------------------------
/// Get the path to ACVP JSON test vectors
/// ----------------------------------------------------------------
fn acvp_json_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("vectors")
        .join("acvp_json")
}

/// ----------------------------------------------------------------
/// Helper to normalize algorithm names from ACVP format to canonical format
/// Strips "ACVP-" prefix and any leading/trailing hyphens
/// ----------------------------------------------------------------
fn normalize_algorithm(raw: &str) -> String {
    let without_prefix = raw.trim().strip_prefix("ACVP-").unwrap_or(raw);
    without_prefix.trim_matches('-').to_string()
}

/// ----------------------------------------------------------------
/// Normalise individual test-case field names so the crypto backend
/// sees all of the canonical keys it understands (`iv`, `pt`, `ct`, ...)
/// ----------------------------------------------------------------
fn canonicalise_inputs(inputs: &mut HashMap<String, FlexValue>) {
    // --------- IV -------------------------------------------------
    if !inputs.contains_key("iv") {
        if let Some(v) = inputs.get("ctr").cloned()
            .or_else(|| inputs.get("nonce").cloned())
        {
            inputs.insert("iv".into(), v);
        }
    }

    // --------- PT / CT --------------------------------------------
    if !inputs.contains_key("pt") {
        if let Some(v) = inputs.get("plaintext").cloned() {
            inputs.insert("pt".into(), v);
        }
    }

    if !inputs.contains_key("ct") {
        if let Some(v) = inputs.get("ciphertext").cloned() {
            inputs.insert("ct".into(), v);
        }
    }
}

/// ----------------------------------------------------------------
/// Public helper to load a specific suite by name
/// ----------------------------------------------------------------
pub fn load_suite_by_name(suite_name: &str) -> Result<TestSuite, String> {
    let suite_dir = acvp_json_dir().join(suite_name);
    
    if !suite_dir.exists() {
        return Err(format!("Suite directory not found: {}", suite_dir.display()));
    }
    
    // Load the prompt.json file which contains the test cases
    let prompt_file = suite_dir.join("prompt.json");
    let json = fs::read_to_string(&prompt_file)
        .map_err(|e| format!("Failed to read {}: {}", prompt_file.display(), e))?;
    
    let mut suite: TestSuite = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;
    
    // Normalize the suite-level algorithm (strip ACVP- prefix, trailing hyphens)
    let base_alg = normalize_algorithm(&suite.algorithm);
    let mode_part = suite.mode.as_ref().map(|m| normalize_algorithm(m));
    
    // For algorithms where the *mode* is really the operation (ECDSA, DSA, RSA…)
    // we keep `algorithm` == "ECDSA" and store the mode in `direction`.
    let asymmetric = matches!(base_alg.as_str(), "ECDSA" | "DSA" | "RSA" | "EdDSA");
    
    let full_algorithm = if asymmetric || mode_part.is_none() {
        base_alg.clone()
    } else {
        let mode = mode_part.as_ref().unwrap();
        // Prevent duplication like "AES-CTR" + "CTR" → "AES-CTR-CTR"
        if base_alg.to_uppercase().ends_with(&mode.to_uppercase()) {
            base_alg.clone()
        } else {
            format!("{}-{}", base_alg, mode)
        }
    };
    
    // Propagate to groups and normalize all algorithm names
    for group in &mut suite.groups {
        // 1. If the group still has the default placeholder, inject the suite value
        if group.algorithm == "AES-CBC" {
            group.algorithm = full_algorithm.clone();
        }
        // 2. Whatever is there, canonicalize it so the dispatcher sees
        //    "AES-CBC", "AES-CTR", etc. without ACVP- prefix or trailing hyphens
        group.algorithm = normalize_algorithm(&group.algorithm);
        
        // If this is an asymmetric suite, copy the mode into `direction`
        if asymmetric {
            if let Some(m) = &mode_part {
                // Only overwrite if the JSON didn't already specify a direction
                if group.direction.is_none() || group.direction.as_deref() == Some("") {
                    group.direction = Some(m.clone());
                }
            }
        }
        
        // 3. Canonicalize the group-level defaults FIRST
        //    This ensures "ctr" → "iv" happens before we copy to test cases
        canonicalise_inputs(&mut group.defaults);
        
        // 4. Copy canonicalized defaults down to each test case
        //    This handles ACVP's pattern of storing common values (iv, key, etc.) at group level
        for tc in &mut group.tests {
            for (k, v) in &group.defaults {
                tc.inputs.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        
        // 5. Canonicalize the test case inputs (for any case-specific fields)
        for tc in &mut group.tests {
            canonicalise_inputs(&mut tc.inputs);
        }
    }
    
    Ok(suite)
}

/// ----------------------------------------------------------------
/// Public helper to load all suites (for compatibility)
/// ----------------------------------------------------------------
pub fn load_all_suites() -> Vec<TestSuite> {
    // For now, just load AES-CBC as an example
    vec![
        load_suite_by_name("ACVP-AES-CBC-1.0").unwrap_or_else(|e| {
            panic!("Failed to load ACVP-AES-CBC-1.0: {}", e);
        })
    ]
}