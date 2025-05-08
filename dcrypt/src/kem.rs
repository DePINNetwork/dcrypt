//! Facade for KEM and key exchange algorithms
//!
//! This module re-exports all KEM algorithms from dcrypt-kem and
//! provides a high-level interface for using them.

// Re-export traditional KEMs
pub use dcrypt_kem::rsa::{RsaKem2048, RsaKem4096};
pub use dcrypt_kem::dh::Dh2048;
pub use dcrypt_kem::ecdh::{EcdhP256, EcdhP384};

// Re-export post-quantum KEMs
pub use dcrypt_kem::kyber::{Kyber512, Kyber768, Kyber1024};
pub use dcrypt_kem::ntru::{NtruHps, NtruEes};
pub use dcrypt_kem::saber::{LightSaber, Saber, FireSaber};
pub use dcrypt_kem::mceliece::{McEliece348864, McEliece6960119};

// Re-export hybrid KEMs
pub use dcrypt_hybrid::kem::{RsaKyberHybrid, EcdhKyberHybrid, EcdhNtruHybrid};
