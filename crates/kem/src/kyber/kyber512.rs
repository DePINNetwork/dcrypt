// kem/src/kyber/kyber512.rs

//! Kyber-512 KEM (NIST PQC Security Level 1).

use super::kem::KyberKem;
use super::params::Kyber512ParamsImpl;

/// Kyber-512 KEM, implementing `api::Kem`.
pub type Kyber512 = KyberKem<Kyber512ParamsImpl>;