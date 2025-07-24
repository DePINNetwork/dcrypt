// kem/src/kyber/kyber1024.rs

//! Kyber-1024 KEM (NIST PQC Security Level 5).

use super::kem::KyberKem;
use super::params::Kyber1024ParamsImpl;

/// Kyber-1024 KEM, implementing `api::Kem`.
pub type Kyber1024 = KyberKem<Kyber1024ParamsImpl>;
