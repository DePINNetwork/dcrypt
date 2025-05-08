//! Type-safe key implementations with algorithm binding
//!
//! Provides key types with compile-time guarantees about their
//! usage and appropriate security properties.

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use dcrypt_core::util::ConstantTimeEquals;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::types::{RandomGeneration, SecureZeroingType, FixedSize, ByteSerializable, ConstantTimeEq as LocalConstantEq};

/// Marker trait for symmetric algorithms
pub trait SymmetricAlgorithm {
    /// Key size in bytes
    const KEY_SIZE: usize;
    
    /// Block size in bytes (if applicable)
    const BLOCK_SIZE: usize;
    
    /// Algorithm identifier
    const ALGORITHM_ID: &'static str;
    
    /// Algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// Marker trait for asymmetric algorithms
pub trait AsymmetricAlgorithm {
    /// Public key size in bytes
    const PUBLIC_KEY_SIZE: usize;
    
    /// Secret key size in bytes
    const SECRET_KEY_SIZE: usize;
    
    /// Algorithm identifier
    const ALGORITHM_ID: &'static str;
    
    /// Algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// A key for a specific symmetric algorithm with fixed size
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey<A: SymmetricAlgorithm, const N: usize> {
    data: [u8; N],
    _algorithm: PhantomData<A>,
}

impl<A: SymmetricAlgorithm, const N: usize> SymmetricKey<A, N> {
    /// Create a new key from an existing array
    pub fn new(data: [u8; N]) -> Self {
        // Runtime check that N == A::KEY_SIZE could be added here
        Self {
            data,
            _algorithm: PhantomData,
        }
    }
    
    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidLength {
                context: "SymmetricKey::from_slice",
                needed: N,
                got: slice.len(),
            });
        }
        
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        
        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }
    
    /// Get the algorithm name
    pub fn algorithm_name() -> String {
        A::name()
    }
    
    /// Get the key size in bytes
    pub fn key_size() -> usize {
        N
    }
}

impl<A: SymmetricAlgorithm, const N: usize> AsRef<[u8]> for SymmetricKey<A, N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<A: SymmetricAlgorithm, const N: usize> AsMut<[u8]> for SymmetricKey<A, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<A: SymmetricAlgorithm, const N: usize> Deref for SymmetricKey<A, N> {
    type Target = [u8; N];
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<A: SymmetricAlgorithm, const N: usize> DerefMut for SymmetricKey<A, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<A: SymmetricAlgorithm, const N: usize> PartialEq for SymmetricKey<A, N> {
    fn eq(&self, other: &Self) -> bool {
        // Use the subtle crate's ConstantTimeEq trait directly
        self.data.as_ref().ct_eq(other.data.as_ref()).into()
    }
}

impl<A: SymmetricAlgorithm, const N: usize> Eq for SymmetricKey<A, N> {}

impl<A: SymmetricAlgorithm, const N: usize> fmt::Debug for SymmetricKey<A, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymmetricKey<{}>[REDACTED]", A::name())
    }
}

impl<A: SymmetricAlgorithm, const N: usize> LocalConstantEq for SymmetricKey<A, N> {
    fn ct_eq(&self, other: &Self) -> bool {
        // Use the ConstantTimeEq trait from subtle
        self.data.as_ref().ct_eq(other.data.as_ref()).into()
    }
}

// Removed conflicting implementation of ConstantTimeEquals for SymmetricKey<A, N>
// The type will use the blanket implementation from dcrypt_core

impl<A: SymmetricAlgorithm, const N: usize> RandomGeneration for SymmetricKey<A, N> {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> dcrypt_core::error::Result<Self> {
        let mut data = [0u8; N];
        rng.fill_bytes(&mut data);
        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }
}

impl<A: SymmetricAlgorithm, const N: usize> SecureZeroingType for SymmetricKey<A, N> {
    fn zeroed() -> Self {
        Self {
            data: [0u8; N],
            _algorithm: PhantomData,
        }
    }
}

impl<A: SymmetricAlgorithm, const N: usize> FixedSize for SymmetricKey<A, N> {
    fn size() -> usize {
        N
    }
}

impl<A: SymmetricAlgorithm, const N: usize> ByteSerializable for SymmetricKey<A, N> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("SymmetricKey::from_bytes")
        })
    }
}

/// A secret key for a specific asymmetric algorithm
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AsymmetricSecretKey<A: AsymmetricAlgorithm, const N: usize> {
    data: [u8; N],
    _algorithm: PhantomData<A>,
}

impl<A: AsymmetricAlgorithm, const N: usize> AsymmetricSecretKey<A, N> {
    /// Create a new key from an existing array
    pub fn new(data: [u8; N]) -> Self {
        // Runtime check that N == A::SECRET_KEY_SIZE could be added here
        Self {
            data,
            _algorithm: PhantomData,
        }
    }
    
    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidLength {
                context: "AsymmetricSecretKey::from_slice",
                needed: N,
                got: slice.len(),
            });
        }
        
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        
        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }
    
    /// Get the algorithm name
    pub fn algorithm_name() -> String {
        A::name()
    }
    
    /// Get the key size in bytes
    pub fn key_size() -> usize {
        N
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> AsRef<[u8]> for AsymmetricSecretKey<A, N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> AsMut<[u8]> for AsymmetricSecretKey<A, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> fmt::Debug for AsymmetricSecretKey<A, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AsymmetricSecretKey<{}>[REDACTED]", A::name())
    }
}

/// A public key for a specific asymmetric algorithm
#[derive(Clone)]
pub struct AsymmetricPublicKey<A: AsymmetricAlgorithm, const N: usize> {
    data: [u8; N],
    _algorithm: PhantomData<A>,
}

impl<A: AsymmetricAlgorithm, const N: usize> AsymmetricPublicKey<A, N> {
    /// Create a new key from an existing array
    pub fn new(data: [u8; N]) -> Self {
        // Runtime check that N == A::PUBLIC_KEY_SIZE could be added here
        Self {
            data,
            _algorithm: PhantomData,
        }
    }
    
    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidLength {
                context: "AsymmetricPublicKey::from_slice",
                needed: N,
                got: slice.len(),
            });
        }
        
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        
        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }
    
    /// Get the algorithm name
    pub fn algorithm_name() -> String {
        A::name()
    }
    
    /// Get the key size in bytes
    pub fn key_size() -> usize {
        N
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> AsRef<[u8]> for AsymmetricPublicKey<A, N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> AsMut<[u8]> for AsymmetricPublicKey<A, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> fmt::Debug for AsymmetricPublicKey<A, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AsymmetricPublicKey<{}>({:?})", A::name(), &self.data[..])
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> PartialEq for AsymmetricPublicKey<A, N> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> Eq for AsymmetricPublicKey<A, N> {}

impl<A: AsymmetricAlgorithm, const N: usize> ByteSerializable for AsymmetricPublicKey<A, N> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("AsymmetricPublicKey::from_bytes")
        })
    }
}