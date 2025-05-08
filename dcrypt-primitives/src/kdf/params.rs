//! Common parameter structures and traits for key derivation functions

#![cfg_attr(not(feature = "std"), no_std)]

// Conditional imports based on available features
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::collections::BTreeMap;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use core::fmt;
use core::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// Trait for algorithms with configurable parameters
pub trait ParamProvider {
    /// The parameter type associated with this algorithm
    type Params: Clone;
    
    /// Creates a new instance with the specified parameters
    fn with_params(params: Self::Params) -> Self;
    
    /// Returns the current parameters
    fn params(&self) -> &Self::Params;
    
    /// Updates the parameters
    fn set_params(&mut self, params: Self::Params);
}

/// Trait for parameter types that can be serialized to a string
pub trait StringEncodable {
    /// Converts the parameters to a string representation
    fn to_string(&self) -> String;
    
    /// Converts from a string representation
    fn from_string(s: &str) -> Result<Self> where Self: Sized;
}

/// A complete password hash with algorithm, parameters, salt, and hash
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash {
    /// The algorithm identifier
    pub algorithm: String,
    
    /// Algorithm-specific parameters
    pub params: BTreeMap<String, String>,
    
    /// The salt used for hashing
    pub salt: Zeroizing<Vec<u8>>,
    
    /// The password hash
    pub hash: Zeroizing<Vec<u8>>,
}

// Manual implementation of Zeroize for PasswordHash
impl Zeroize for PasswordHash {
    fn zeroize(&mut self) {
        self.algorithm.zeroize();
        // BTreeMap doesn't implement Zeroize, so we can't zeroize it directly
        // The sensitive data is in salt and hash which are Zeroizing<Vec<u8>>
        // and will be zeroized automatically
    }
}

impl PasswordHash {
    /// Creates a new password hash
    pub fn new(
        algorithm: String,
        params: BTreeMap<String, String>,
        salt: Vec<u8>,
        hash: Vec<u8>,
    ) -> Self {
        Self {
            algorithm,
            params,
            salt: Zeroizing::new(salt),
            hash: Zeroizing::new(hash),
        }
    }
    
    /// Extracts a parameter value by key
    pub fn param(&self, key: &str) -> Option<&String> {
        self.params.get(key)
    }
    
    /// Parses a parameter as an integer
    pub fn param_as_u32(&self, key: &str) -> Result<u32> {
        match self.param(key) {
            Some(value) => value.parse::<u32>().map_err(|_| 
                Error::InvalidParameter("Invalid parameter value")),
            None => Err(Error::InvalidParameter("Missing parameter"))
        }
    }
}

// String encoding for PasswordHash in PHC format
// $algorithm$param=value,param=value$salt$hash
impl fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${}", self.algorithm)?;
        
        if !self.params.is_empty() {
            write!(f, "$")?;
            let mut first = true;
            for (key, value) in &self.params {
                if !first {
                    write!(f, ",")?;
                }
                write!(f, "{}={}", key, value)?;
                first = false;
            }
        }
        
        // Encode salt and hash in base64
        let salt_b64 = base64_encode(&self.salt);
        let hash_b64 = base64_encode(&self.hash);
        
        write!(f, "${}${}", salt_b64, hash_b64)
    }
}

impl FromStr for PasswordHash {
    type Err = Error;
    
    fn from_str(s: &str) -> Result<Self> {
        if !s.starts_with('$') {
            return Err(Error::InvalidParameter("Invalid password hash format"));
        }
        
        let parts: Vec<&str> = s.split('$').skip(1).collect();
        if parts.len() < 3 {
            return Err(Error::InvalidParameter("Invalid password hash format"));
        }
        
        let algorithm = parts[0].to_string();
        
        // Parse parameters if present
        let mut params = BTreeMap::new();
        if parts.len() > 3 {
            for param_str in parts[1].split(',') {
                if param_str.is_empty() {
                    continue;
                }
                
                let param_parts: Vec<&str> = param_str.split('=').collect();
                if param_parts.len() != 2 {
                    return Err(Error::InvalidParameter("Invalid parameter format"));
                }
                
                params.insert(param_parts[0].to_string(), param_parts[1].to_string());
            }
        }
        
        // Parse salt and hash
        let salt_idx = if parts.len() > 3 { 2 } else { 1 };
        let hash_idx = if parts.len() > 3 { 3 } else { 2 };
        
        let salt = base64_decode(parts[salt_idx])
            .map_err(|_| Error::InvalidParameter("Invalid salt encoding"))?;
            
        let hash = base64_decode(parts[hash_idx])
            .map_err(|_| Error::InvalidParameter("Invalid hash encoding"))?;
        
        Ok(PasswordHash {
            algorithm,
            params,
            salt: Zeroizing::new(salt),
            hash: Zeroizing::new(hash),
        })
    }
}

// Simple Base64 encoding/decoding functions
// Note: In a real implementation, you'd use a proper base64 library

fn base64_encode(data: &[u8]) -> String {
    // This is a stub - in a real implementation, use a proper base64 library
    let encoded = data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    encoded
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    // This is a stub - in a real implementation, use a proper base64 library
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();
    
    while chars.peek().is_some() {
        let high = chars.next().ok_or(Error::InvalidParameter("Invalid hex encoding"))?;
        let low = chars.next().ok_or(Error::InvalidParameter("Invalid hex encoding"))?;
        
        let byte = u8::from_str_radix(&format!("{}{}", high, low), 16)
            .map_err(|_| Error::InvalidParameter("Invalid hex encoding"))?;
            
        result.push(byte);
    }
    
    Ok(result)
}