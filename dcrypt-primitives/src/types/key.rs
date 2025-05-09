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
use crate::types::sealed::Sealed;
use crate::types::{ValidKeySize, ValidSecretKeySize, ValidPublicKeySize};

// Add these imports to fix the "cannot find type" errors
use crate::Aes128;
use crate::Aes256;
use crate::ChaCha20;
use crate::ChaCha20Poly1305;
use crate::Ed25519;
use crate::X25519;

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

// Mark types as sealed to prevent external implementations
impl<A: SymmetricAlgorithm, const N: usize> Sealed for SymmetricKey<A, N> {}

// Individual implementations for specific algorithm and size combinations
impl ValidKeySize<Aes128, 16> for SymmetricKey<Aes128, 16> {}
impl ValidKeySize<Aes256, 32> for SymmetricKey<Aes256, 32> {}
impl ValidKeySize<ChaCha20, 32> for SymmetricKey<ChaCha20, 32> {}
impl ValidKeySize<ChaCha20Poly1305, 32> for SymmetricKey<ChaCha20Poly1305, 32> {}

impl<A: SymmetricAlgorithm, const N: usize> SymmetricKey<A, N>
where
    Self: ValidKeySize<A, N>,
{
    /// Create a new key from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self {
            data,
            _algorithm: PhantomData,
        }
    }
    
    /// Create from a slice, if it has the correct length
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != N {
            return Err(Error::InvalidLength {
                context: "SymmetricKey::from_slice",
                needed: N,
                got: bytes.len(),
            });
        }
        
        let mut data = [0u8; N];
        data.copy_from_slice(bytes);
        
        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }
    
    /// Create a zeroed key (not recommended for cryptographic use)
    pub fn zeroed() -> Self {
        Self {
            data: [0u8; N],
            _algorithm: PhantomData,
        }
    }
    
    /// Unchecked constructor for internal use
    #[doc(hidden)]
    pub(crate) fn new_unchecked(data: [u8; N]) -> Self {
        Self {
            data,
            _algorithm: PhantomData,
        }
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
        Self::zeroed()
    }
}

impl<A: SymmetricAlgorithm, const N: usize> FixedSize for SymmetricKey<A, N> {
    fn size() -> usize {
        N
    }
}

// Implement ByteSerializable only for specific valid combinations
impl ByteSerializable for SymmetricKey<Aes128, 16> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::try_from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("SymmetricKey<Aes128, 16>::from_bytes")
        })
    }
}

impl ByteSerializable for SymmetricKey<Aes256, 32> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::try_from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("SymmetricKey<Aes256, 32>::from_bytes")
        })
    }
}

impl ByteSerializable for SymmetricKey<ChaCha20, 32> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::try_from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("SymmetricKey<ChaCha20, 32>::from_bytes")
        })
    }
}

impl ByteSerializable for SymmetricKey<ChaCha20Poly1305, 32> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::try_from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("SymmetricKey<ChaCha20Poly1305, 32>::from_bytes")
        })
    }
}

/// A secret key for a specific asymmetric algorithm
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AsymmetricSecretKey<A: AsymmetricAlgorithm, const N: usize> {
    data: [u8; N],
    _algorithm: PhantomData<A>,
}

// Mark types as sealed to prevent external implementations
impl<A: AsymmetricAlgorithm, const N: usize> Sealed for AsymmetricSecretKey<A, N> {}

// Individual implementations for specific algorithm and size combinations
impl ValidSecretKeySize<Ed25519, 32> for AsymmetricSecretKey<Ed25519, 32> {}
impl ValidSecretKeySize<X25519, 32> for AsymmetricSecretKey<X25519, 32> {}

impl<A: AsymmetricAlgorithm, const N: usize> AsymmetricSecretKey<A, N>
where
    Self: ValidSecretKeySize<A, N>,
{
    /// Create a new key from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self {
            data,
            _algorithm: PhantomData,
        }
    }
    
    /// Create from a slice, if it has the correct length
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != N {
            return Err(Error::InvalidLength {
                context: "AsymmetricSecretKey::from_slice",
                needed: N,
                got: bytes.len(),
            });
        }
        
        let mut data = [0u8; N];
        data.copy_from_slice(bytes);
        
        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }
    
    /// Create a zeroed key (not recommended for cryptographic use)
    pub fn zeroed() -> Self {
        Self {
            data: [0u8; N],
            _algorithm: PhantomData,
        }
    }
    
    /// Unchecked constructor for internal use
    #[doc(hidden)]
    pub(crate) fn new_unchecked(data: [u8; N]) -> Self {
        Self {
            data,
            _algorithm: PhantomData,
        }
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

impl<A: AsymmetricAlgorithm, const N: usize> FixedSize for AsymmetricSecretKey<A, N> {
    fn size() -> usize {
        N
    }
}

// Implement ByteSerializable only for specific valid combinations
impl ByteSerializable for AsymmetricSecretKey<Ed25519, 32> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::try_from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("AsymmetricSecretKey<Ed25519, 32>::from_bytes")
        })
    }
}

impl ByteSerializable for AsymmetricSecretKey<X25519, 32> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::try_from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("AsymmetricSecretKey<X25519, 32>::from_bytes")
        })
    }
}

/// A public key for a specific asymmetric algorithm
#[derive(Clone)]
pub struct AsymmetricPublicKey<A: AsymmetricAlgorithm, const N: usize> {
    data: [u8; N],
    _algorithm: PhantomData<A>,
}

// Mark types as sealed to prevent external implementations
impl<A: AsymmetricAlgorithm, const N: usize> Sealed for AsymmetricPublicKey<A, N> {}

// Individual implementations for specific algorithm and size combinations
impl ValidPublicKeySize<Ed25519, 32> for AsymmetricPublicKey<Ed25519, 32> {}
impl ValidPublicKeySize<X25519, 32> for AsymmetricPublicKey<X25519, 32> {}

impl<A: AsymmetricAlgorithm, const N: usize> AsymmetricPublicKey<A, N>
where
    Self: ValidPublicKeySize<A, N>,
{
    /// Create a new key from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self {
            data,
            _algorithm: PhantomData,
        }
    }
    
    /// Create from a slice, if it has the correct length
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != N {
            return Err(Error::InvalidLength {
                context: "AsymmetricPublicKey::from_slice",
                needed: N,
                got: bytes.len(),
            });
        }
        
        let mut data = [0u8; N];
        data.copy_from_slice(bytes);
        
        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }
    
    /// Unchecked constructor for internal use
    #[doc(hidden)]
    pub(crate) fn new_unchecked(data: [u8; N]) -> Self {
        Self {
            data,
            _algorithm: PhantomData,
        }
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

impl<A: AsymmetricAlgorithm, const N: usize> FixedSize for AsymmetricPublicKey<A, N> {
    fn size() -> usize {
        N
    }
}

// Implement ByteSerializable only for specific valid combinations
impl ByteSerializable for AsymmetricPublicKey<Ed25519, 32> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::try_from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("AsymmetricPublicKey<Ed25519, 32>::from_bytes")
        })
    }
}

impl ByteSerializable for AsymmetricPublicKey<X25519, 32> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> dcrypt_core::error::Result<Self> {
        Self::try_from_slice(bytes).map_err(|e| {
            let core_err = dcrypt_core::error::DcryptError::from(e);
            core_err.with_context("AsymmetricPublicKey<X25519, 32>::from_bytes")
        })
    }
}