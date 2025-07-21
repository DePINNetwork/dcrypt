//! Extensible dispatcher for ACVP algorithm handlers

use std::collections::HashMap;
use once_cell::sync::Lazy;

use super::model::{TestCase, TestGroup};
use super::error::{Result, EngineError};

/// Registry key for looking up handlers
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct DispatchKey {
    pub algo: String,
    pub dir:  String, // "function" from ACVP JSON (e.g., "encapsulation", "decapsulation")
    pub kind: String, // "testType" from ACVP JSON (e.g., "AFT")
}

/// Handler function type
pub type HandlerFn = fn(&TestGroup, &TestCase) -> Result<()>;

/// Global registry of algorithm handlers
pub static REGISTRY: Lazy<HashMap<DispatchKey, HandlerFn>> = Lazy::new(|| {
    let mut m = HashMap::<DispatchKey, HandlerFn>::new();
    
    // Register all algorithm modules
    super::algorithms::aes_cbc::register(&mut m);
    super::algorithms::aes_ctr::register(&mut m);
    super::algorithms::aes_gcm::register(&mut m);
    super::algorithms::ecdsa::register(&mut m);
    super::algorithms::ml_kem::register(&mut m);
    super::algorithms::ml_dsa::register(&mut m); 
    super::algorithms::eddsa::register(&mut m);
    super::algorithms::sha2::register(&mut m);
    super::algorithms::sha3::register(&mut m);
    super::algorithms::shake::register(&mut m);
    m
});

/// Helper function for registering handlers
pub fn insert(
    map: &mut HashMap<DispatchKey, HandlerFn>,
    algo: &str,  // e.g., "ML-KEM", "AES-CBC"
    dir:  &str,  // Corresponds to "function" or "direction"
    kind: &str,  // Corresponds to "testType" like "AFT", "MCT"
    handler: HandlerFn,
) {
    map.insert(DispatchKey { 
        algo: algo.to_string(), 
        dir: dir.to_string(), 
        kind: kind.to_string() 
    }, handler);
}