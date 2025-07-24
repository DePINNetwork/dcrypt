//! Trait definition for serialization

use crate::Result;

/// Trait for objects that can be serialized to and from bytes
pub trait Serialize: Sized {
    /// Convert the object to a byte array
    fn to_bytes(&self) -> Result<Vec<u8>>;

    /// Create an object from a byte array
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}
