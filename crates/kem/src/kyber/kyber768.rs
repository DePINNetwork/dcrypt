// kem/src/kyber/kyber768.rs

//! Kyber-768 KEM (NIST PQC Security Level 3).

use super::kem::KyberKem;
use super::params::Kyber768ParamsImpl;

/// Kyber-768 KEM, implementing `api::Kem`.
pub type Kyber768 = KyberKem<Kyber768ParamsImpl>;