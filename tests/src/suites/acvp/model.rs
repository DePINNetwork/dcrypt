//! Pure data model for ACVP-style test vectors.
//! No dependency on the rest of the framework.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;

/// Flexible value that can be either string, number, bool, array, object, or null
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FlexValue {
    String(String),
    Number(serde_json::Number),
    Bool(bool),
    Array(Vec<FlexValue>),
    Object(HashMap<String, FlexValue>),
    Null,
}

impl FlexValue {
    pub fn as_string(&self) -> String {
        match self {
            FlexValue::String(s) => s.clone(),
            FlexValue::Number(n) => n.to_string(),
            FlexValue::Bool(b) => b.to_string(),
            FlexValue::Array(arr) => {
                serde_json::to_string(arr).unwrap_or_else(|_| format!("{:?}", arr))
            }
            FlexValue::Object(obj) => {
                serde_json::to_string(obj).unwrap_or_else(|_| format!("{:?}", obj))
            }
            FlexValue::Null => String::new(),
        }
    }
}

/// ----------------------------------------------------------------
/// 1. Leaf-level test case
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestCase {
    #[serde(rename = "tcId")]
    pub test_id: u64,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(flatten)]
    pub inputs: HashMap<String, FlexValue>, // Changed from String to FlexValue
    #[serde(skip)]
    pub outputs: RefCell<HashMap<String, String>>, // For storing computed results
    #[serde(default = "default_expected_result")]
    pub expected_result: String, // valid / invalid / fail
    #[serde(default)]
    pub error_contains: Option<String>,
}

fn default_expected_result() -> String {
    "valid".into()
}

/// ----------------------------------------------------------------
/// 2. Groups (ACVP terminology) – often share parameters
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestGroup {
    #[serde(rename = "tgId")]
    pub group_name: u64,
    #[serde(rename = "testType")]
    pub test_type: String, // AFT / MCT / ...
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub direction: Option<String>, // encrypt / decrypt
    #[serde(default)]
    pub key_len: Option<u32>,
    #[serde(default)]
    pub params: Option<serde_json::Value>,

    /// Any other ACVP fields (iv, ctr, nonce, key, payloadLen, ...)
    /// These are group-level defaults that apply to all test cases
    #[serde(flatten)]
    pub defaults: HashMap<String, FlexValue>,

    pub tests: Vec<TestCase>,
}

fn default_algorithm() -> String {
    "AES-CBC".into()
}

/// ----------------------------------------------------------------
/// 3. Vector set info
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorSetInfo {
    pub vector_set_id: u64,
    pub algorithm: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub revision: Option<String>,
}

/// ----------------------------------------------------------------
/// 4. Whole suite (file) – ACVP JSON format
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestSuite {
    #[serde(rename = "vsId")]
    pub suite_name: u64,
    #[serde(default = "default_suite_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub mode: Option<String>, // Added mode field to capture ACVP mode
    #[serde(rename = "testGroups")]
    pub groups: Vec<TestGroup>,
}

fn default_suite_algorithm() -> String {
    "AES-CBC".into()
}

/// ----------------------------------------------------------------
/// 5. Build-time stub emitted by build.rs (not used for now)
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
pub struct SuiteMeta {
    pub algorithm: String,
    pub operation: String,
    pub manifest: String,   // directory that holds JSON files
    pub files: Vec<String>, // typically 4 JSON files
}
