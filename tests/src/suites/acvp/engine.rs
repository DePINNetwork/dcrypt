// tests/src/suites/acvp/engine.rs
//! Enhanced ACVP engine with optimizations and better error handling

use crate::suites::acvp::model::{TestGroup, TestCase};
use crate::suites::acvp::runner::AcvpEngine;
use crate::suites::acvp::error::{EngineError, Result};
use algorithms as alg;
use arrayref::array_ref;

/// Concrete type used by tests: one instance suffices for all suites.
pub struct DcryptEngine;

impl AcvpEngine for DcryptEngine {
    fn run(&self, group: &TestGroup, case: &TestCase) -> std::result::Result<(), String> {
        // Convert our Result to String for compatibility
        self.run_internal(group, case)
            .map_err(|e| e.to_string())
    }
}

impl DcryptEngine {
    fn run_internal(&self, group: &TestGroup, case: &TestCase) -> Result<()> {
        use super::dispatcher::{DispatchKey, REGISTRY};
        
        // Determine the operation direction/function for the DispatchKey
        // For KEMs, the JSON uses "function" (e.g., "encapsulation").
        // For symmetric ciphers, it's "direction" (e.g., "encrypt").
        // The loader normalizes algorithm 'mode' to 'group.direction' for ECDSA,
        // but "function" is separate.
        let operation_key = group.defaults.get("function").map(|v| v.as_string()) // Check group defaults first
            .or_else(|| group.params.as_ref() // Then group params (as seen in ML-KEM JSON structure)
                .and_then(|p_val| p_val.as_object())
                .and_then(|p_map| p_map.get("function"))
                .and_then(|f_val| f_val.as_str().map(|s| s.to_string())))
            .or_else(|| group.direction.clone()) // Fallback to group.direction
            .unwrap_or_else(|| group.test_type.clone()); // Ultimate fallback to test_type if nothing else found

        let key = DispatchKey {
            algo: group.algorithm.clone(),
            dir:  operation_key,
            kind: group.test_type.clone(),
        };
        
        REGISTRY.get(&key)
            .ok_or_else(|| EngineError::Crypto(format!("unsupported {:?}", key)))?
            (group, case)
    }
}

/// Helper to safely create a Nonce from a slice
/// This is kept here as it's used by multiple algorithm modules
pub fn make_nonce(iv: &[u8]) -> Result<alg::types::Nonce<16>> {
    if iv.len() != 16 {
        return Err(EngineError::InvalidData(
            format!("Invalid IV length: {}", iv.len())
        ));
    }
    Ok(alg::types::Nonce::<16>::new(*array_ref![iv, 0, 16]))
}