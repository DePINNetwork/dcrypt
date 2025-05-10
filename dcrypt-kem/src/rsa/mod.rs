//! RSA-based Key Encapsulation Mechanism (RSA-KEM)
//!
//! This module implements RSA-KEM as specified in IEEE 1363a-2004.

mod common;
mod rsa2048;
mod rsa4096;

pub use rsa2048::RsaKem2048;
pub use rsa4096::RsaKem4096;