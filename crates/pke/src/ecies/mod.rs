//! Elliptic Curve Integrated Encryption Scheme (ECIES) generic components.

use algorithms::kdf::hkdf::Hkdf;
use algorithms::hash::sha2::{Sha256, Sha384, Sha512}; // Added Sha512
use algorithms::kdf::KeyDerivationFunction;
use crate::error::{Result as PkeResult, Error as PkeError}; // Use PKE specific Result/Error

// Ensure Vec, String, format are available for no_std + alloc
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::string::String; 
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::format;

// Declare submodules
pub mod p192; // Added P-192 module
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521; 

// Re-export the main structs
pub use p192::EciesP192; // Added P-192 export
pub use p224::EciesP224; 
pub use p256::EciesP256;
pub use p384::EciesP384;
pub use p521::EciesP521; 

// --- Constants and Helper Structs/Functions (moved from individual files if generic enough, or keep here) ---

// Key lengths for AEADs
pub(crate) const CHACHA20POLY1305_KEY_LEN: usize = 32;
pub(crate) const AES256GCM_KEY_LEN: usize = 32;

// Nonce lengths for AEADs
pub(crate) const CHACHA20POLY1305_NONCE_LEN: usize = 12;
pub(crate) const AES256GCM_NONCE_LEN: usize = 12;

/// Derives symmetric key from an ECDH shared secret using HKDF-SHA256.
pub(crate) fn derive_symmetric_key_hkdf_sha256(
    shared_secret_z: &[u8],    // x-coordinate of shared point
    ephemeral_pk_bytes: &[u8], // Ephemeral public key R (salt for HKDF)
    key_output_len: usize,     // Length of the symmetric key to derive
    info: Option<&[u8]>,
) -> PkeResult<Vec<u8>> {
    let kdf = Hkdf::<Sha256>::new();
    kdf.derive_key(shared_secret_z, Some(ephemeral_pk_bytes), info, key_output_len)
       .map_err(PkeError::from)
}

/// Derives symmetric key from an ECDH shared secret using HKDF-SHA384.
pub(crate) fn derive_symmetric_key_hkdf_sha384(
    shared_secret_z: &[u8],
    ephemeral_pk_bytes: &[u8],
    key_output_len: usize,
    info: Option<&[u8]>,
) -> PkeResult<Vec<u8>> {
    let kdf = Hkdf::<Sha384>::new();
    kdf.derive_key(shared_secret_z, Some(ephemeral_pk_bytes), info, key_output_len)
       .map_err(PkeError::from)
}

/// Derives symmetric key from an ECDH shared secret using HKDF-SHA512.
pub(crate) fn derive_symmetric_key_hkdf_sha512(
    shared_secret_z: &[u8],
    ephemeral_pk_bytes: &[u8],
    key_output_len: usize,
    info: Option<&[u8]>,
) -> PkeResult<Vec<u8>> {
    let kdf = Hkdf::<Sha512>::new();
    kdf.derive_key(shared_secret_z, Some(ephemeral_pk_bytes), info, key_output_len)
       .map_err(PkeError::from)
}

/// Internal structure for ECIES ciphertext components.
/// Format on wire: R_len (1 byte) || R || N_len (1 byte) || N || CT_len (4 bytes) || (C||T)
#[derive(Clone, Debug)]
pub(crate) struct EciesCiphertextComponents {
    pub ephemeral_public_key: Vec<u8>, // R
    pub aead_nonce: Vec<u8>,           // N
    pub aead_ciphertext_tag: Vec<u8>,  // C || T (AEAD output)
}

impl EciesCiphertextComponents {
    pub fn serialize(&self) -> Vec<u8> {
        let r_len = self.ephemeral_public_key.len();
        let n_len = self.aead_nonce.len();
        let ct_t_len = self.aead_ciphertext_tag.len();

        assert!(r_len <= u8::MAX as usize, "Ephemeral PK too long for 1-byte length prefix");
        assert!(n_len <= u8::MAX as usize, "AEAD Nonce too long for 1-byte length prefix");

        let total_len = 1 + r_len + 1 + n_len + 4 + ct_t_len;
        let mut serialized = Vec::with_capacity(total_len);

        serialized.push(r_len as u8);
        serialized.extend_from_slice(&self.ephemeral_public_key);

        serialized.push(n_len as u8);
        serialized.extend_from_slice(&self.aead_nonce);

        serialized.extend_from_slice(&(ct_t_len as u32).to_be_bytes());
        serialized.extend_from_slice(&self.aead_ciphertext_tag);
        serialized
    }

    pub fn deserialize(bytes: &[u8]) -> PkeResult<Self> {
        if bytes.is_empty() {
            return Err(PkeError::InvalidCiphertextFormat("empty input for deserialization"));
        }
        let mut current_pos = 0;

        if bytes.len() < current_pos + 1 {
            return Err(PkeError::InvalidCiphertextFormat("R length truncated"));
        }
        let r_len = bytes[current_pos] as usize;
        current_pos += 1;
        if bytes.len() < current_pos + r_len {
            return Err(PkeError::InvalidCiphertextFormat("R data truncated"));
        }
        let ephemeral_public_key = bytes[current_pos..current_pos + r_len].to_vec();
        current_pos += r_len;

        if bytes.len() < current_pos + 1 {
             return Err(PkeError::InvalidCiphertextFormat("Nonce length truncated"));
        }
        let n_len = bytes[current_pos] as usize;
        current_pos += 1;
        if bytes.len() < current_pos + n_len {
            return Err(PkeError::InvalidCiphertextFormat("Nonce data truncated"));
        }
        let aead_nonce = bytes[current_pos..current_pos + n_len].to_vec();
        current_pos += n_len;

        if bytes.len() < current_pos + 4 {
            return Err(PkeError::InvalidCiphertextFormat("AEAD payload length truncated"));
        }
        let ct_t_len = u32::from_be_bytes(
            bytes[current_pos..current_pos + 4].try_into()
                .map_err(|_| PkeError::InvalidCiphertextFormat("Failed to read AEAD payload length"))?
        ) as usize;
        current_pos += 4;

        if bytes.len() < current_pos + ct_t_len {
            return Err(PkeError::InvalidCiphertextFormat("AEAD payload data truncated"));
        }
        let aead_ciphertext_tag = bytes[current_pos..current_pos + ct_t_len].to_vec();
        current_pos += ct_t_len;

        if current_pos != bytes.len() {
            return Err(PkeError::InvalidCiphertextFormat("trailing data after deserialization"));
        }

        Ok(Self {
            ephemeral_public_key,
            aead_nonce,
            aead_ciphertext_tag,
        })
    }
}