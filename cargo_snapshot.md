# Cargo.toml Snapshot: dcrypt
Created: Sat Jul 26 01:56:18 PM EDT 2025
Target: /home/levijosman/depin-network/codebase/dcrypt

## Workspace Structure

```
/home/levijosman/depin-network/codebase/dcrypt
├── Cargo.toml
├── crates
│   ├── algorithms
│   │   └── Cargo.toml
│   ├── api
│   │   └── Cargo.toml
│   ├── common
│   │   └── Cargo.toml
│   ├── hybrid
│   │   └── Cargo.toml
│   ├── internal
│   │   └── Cargo.toml
│   ├── kem
│   │   └── Cargo.toml
│   ├── params
│   │   └── Cargo.toml
│   ├── pke
│   │   └── Cargo.toml
│   ├── sign
│   │   └── Cargo.toml
│   ├── symmetric
│   │   └── Cargo.toml
│   └── utils
│       └── Cargo.toml
└── tests
    └── Cargo.toml

13 directories, 13 files
```

## Cargo.toml Files

## Root Workspace: Cargo.toml

```toml
[package]
name = "dcrypt"
version.workspace = true
edition.workspace = true
authors.workspace = true
description.workspace = true
repository.workspace = true
license.workspace = true
readme.workspace = true
categories.workspace = true
keywords.workspace = true

[dependencies]
# Core dependencies (always included)
dcrypt-api = { version = "=0.11.0-beta.1", path = "crates/api" }
dcrypt-common = { version = "=0.11.0-beta.1", path = "crates/common" }
dcrypt-internal = { version = "=0.11.0-beta.1", path = "crates/internal" }
dcrypt-params = { version = "=0.11.0-beta.1", path = "crates/params" }

# Optional algorithm crates
dcrypt-algorithms = { version = "=0.11.0-beta.1", path = "crates/algorithms", optional = true }
dcrypt-symmetric = { version = "=0.11.0-beta.1", path = "crates/symmetric", optional = true }
dcrypt-kem = { version = "=0.11.0-beta.1", path = "crates/kem", optional = true }
dcrypt-sign = { version = "=0.11.0-beta.1", path = "crates/sign", optional = true }
dcrypt-pke = { version = "=0.11.0-beta.1", path = "crates/pke", optional = true }
dcrypt-hybrid = { version = "=0.11.0-beta.1", path = "crates/hybrid", optional = true }

# Re-export workspace dependencies that users might need
rand = { workspace = true, optional = true }
zeroize = { workspace = true }
subtle = { workspace = true }
serde = { workspace = true, optional = true }
thiserror = { workspace = true, optional = true }

[features]
# Default includes common traditional algorithms
default = ["std", "traditional"]

# Standard library support
std = [
    "rand?/std",
    "dcrypt-api/std",
    "dcrypt-common/std",
    "dcrypt-internal/std",
    "dcrypt-algorithms?/std",
    "dcrypt-symmetric?/std",
    "dcrypt-kem?/std",
    "dcrypt-sign?/std",
    "dcrypt-pke?/std",
    "dcrypt-hybrid?/std"
]

# Algorithm categories
traditional = ["dep:dcrypt-algorithms", "dep:dcrypt-symmetric", "dcrypt-kem?/traditional", "dcrypt-sign?/traditional", "dep:dcrypt-pke"]
post-quantum = ["dcrypt-kem?/post-quantum", "dcrypt-sign?/post-quantum"]
hybrid = ["dep:dcrypt-hybrid", "traditional", "post-quantum"]

# Individual components
algorithms = ["dep:dcrypt-algorithms"]
symmetric = ["dep:dcrypt-symmetric"]
kem = ["dep:dcrypt-kem"]
sign = ["dep:dcrypt-sign"]
pke = ["dep:dcrypt-pke"]

# Other features
alloc = []
serde = ["dep:serde", "dep:thiserror"]
full = ["std", "alloc", "serde", "traditional", "post-quantum", "hybrid", "algorithms", "symmetric", "kem", "sign", "pke"]

# Workspace configuration
[workspace]
members = [
    "crates/api",
    "crates/common",
    "crates/internal",
    "crates/params",       
    "crates/algorithms", 
    "crates/symmetric",
    "crates/kem",
    "crates/sign",
    "crates/hybrid",
    "crates/pke",
    "crates/utils",
    "tests"
]
resolver = "2"

[workspace.package]
version     = "0.11.0-beta.1"
edition     = "2021"
authors     = ["Heath Ledger"]
description = "dcrypt is a pure Rust software-only cryptographic library for DePIN Network's Web4 infrastructure framework providing both traditional and post-quantum cryptography. Designed with emphasis on security, modularity, performance, and usability, dcrypt eliminates foreign function interfaces (FFI) ensuring memory safety and cross-platform compatibility."
repository  = "https://github.com/DePINNetwork/dcrypt"
license     = "Apache-2.0"
readme      = "README.md"
categories  = ["cryptography", "no-std"]
keywords    = ["cryptography", "post-quantum", "crypto"]

[workspace.dependencies]
rand        = { version = "0.8.5", default-features = false }
rand_chacha = "0.3.1"
zeroize     = { version = "1.8.1", features = ["zeroize_derive"] }
subtle      = { version = "2.6.1", default-features = false }
serde       = { version = "1.0.219", features = ["derive"] }
thiserror   = { version = "1.0.69" }

# Dev dependencies for tests
[dev-dependencies]
criterion = "0.5"
proptest = "1.0"

[workspace.metadata.release]
# All crates share the same version
shared-version = true

# How to handle version updates for dependencies
# "upgrade" means update all workspace members' versions in lockstep
dependent-version = "upgrade"

# Don't automatically push or tag - we'll do it manually
push = false
tag = false

# Don't publish automatically - we'll use a separate command
publish = false

# Create a single commit for all version updates
consolidate-commits = true

# Commit message template
pre-release-commit-message = "chore: release version {{version}}"

# Sign commits for security (optional - remove if you don't have GPG set up)
sign-commit = false
sign-tag = false

# For the root package specifically
[package.metadata.release]
# The root crate should be published
publish = true
```

## Internal Crate: crates/algorithms/Cargo.toml

```toml
[package]
name = "dcrypt-algorithms"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Cryptographic primitives for the dcrypt library"
repository.workspace = true
license.workspace = true
publish = true

[features]
# Default features
default = ["std", "xof", "ec"]

# Standard library support - enables all features
std = [
    "alloc",
    "byteorder/std",
    "subtle/std",
    "hex/std",
    "rand/std",
    "getrandom/std",
    "serde_json",
    # Forward std to dependencies
    "dcrypt-api/std",
    "dcrypt-common/std",
    "dcrypt-internal/std",
    # Enable all algorithm features with std
    "hash", "xof", "aead", "block", "kdf", "mac", "stream", "ec"
]

# Allocator support - provides Vec, Box, String, etc.
alloc = [
    "dcrypt-api/alloc",
    "dcrypt-common/alloc",
]

# Algorithm feature groups
hash = []
xof = ["alloc"]
aead = ["alloc"]
block = []
kdf = ["alloc"]
mac = []
stream = []
ec = ["alloc"]

# Optional features
serde_json = ["dep:serde_json", "dep:serde"]

[dependencies]
# Internal dependencies
dcrypt-api = { path = "../api", version = "=0.11.0-beta.1", default-features = false }
dcrypt-common = { path = "../common", version = "=0.11.0-beta.1", default-features = false }
dcrypt-internal = { path = "../internal", version = "=0.11.0-beta.1", default-features = false }
dcrypt-params = { path = "../params", version = "=0.11.0-beta.1" }

# Core cryptographic dependencies
zeroize = { version = "1.5.7", features = ["zeroize_derive"] }
subtle = { version = "2.6.1", default-features = false }
byteorder = { version = "1.4.3", default-features = false }

# Encoding/serialization
hex = { version = "0.4.3", default-features = false }
base64 = { version = "0.22.1", default-features = false, features = ["alloc"] }
faster-hex = { version = "0.6.1", optional = true }
serde = { version = "1.0.189", features = ["derive"], optional = true }
serde_json = { version = "1.0.107", optional = true }

# Random number generation
rand = { version = "0.8.5", default-features = false }
getrandom = { version = "0.2.15", default-features = false, optional = true, features = ["custom"] }

# Platform-specific dependencies
portable-atomic = { version = "1.6", default-features = false }

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
rand_chacha = { version = "0.3.1", default-features = false }

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
serde = { version = "1.0.189", features = ["derive"] }
serde_json = "1.0.107"
rand = { version = "0.8.5", features = ["std", "std_rng"] }
rand_chacha = "0.3.1"

[[bench]]
name = "aes"
harness = false

[[bench]]
name = "aes_gcm"
harness = false

[[bench]]
name = "sha2"
harness = false

[[bench]]
name = "chacha20_poly1305"
harness = false

[[bench]]
name = "k256"
harness = false

[[bench]]
name = "xchacha20_poly1305"
harness = false

[[bench]]
name = "p256"
harness = false

[[bench]]
name = "p384"
harness = false

[[bench]]
name = "p521"
harness = false

[[bench]]
name = "b283k"
harness = false

[[bench]]
name = "argon2"
harness = false

[[bench]]
name = "ntt"
harness = false

[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]

[package.metadata.release]
publish = true
```

## Internal Crate: crates/api/Cargo.toml

```toml
[package]
name = "dcrypt-api"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Public API traits and types for the dcrypt library"
repository.workspace = true
license.workspace = true
publish = true 

[features]
default = ["std"]
std = ["thiserror", "zeroize/std", "alloc"]
alloc = []
no_std = []
serde = ["dep:serde"]

[dependencies]
zeroize = { version = "1.5.7", features = ["zeroize_derive"] }
thiserror = { version = "1.0.37", optional = true }
subtle = { version = "2.4.1" }
serde = { version = "1.0.147", features = ["derive"], optional = true }
rand = { version = "0.8.5", optional = false }
dcrypt-internal = { path = "../internal", version = "=0.11.0-beta.1" }

[dev-dependencies]
rand = { version = "0.8.5" }

[package.metadata.release]
publish = true
```

## Internal Crate: crates/common/Cargo.toml

```toml
[package]
name = "dcrypt-common"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Common implementations and shared functionality for the dcrypt library"
repository.workspace = true
license.workspace = true
publish = true

[features]
default = ["std"]
std = ["thiserror", "zeroize/std", "alloc"]
alloc = []
no_std = []
serde = ["dep:serde"]

[dependencies]
zeroize = { version = "1.5.7", features = ["zeroize_derive"] }
thiserror = { version = "1.0.37", optional = true }
subtle = { version = "2.4.1" }
serde = { version = "1.0.147", features = ["derive"], optional = true }
rand = { version = "0.8.5", optional = false }
dcrypt-internal = { path = "../internal", version = "=0.11.0-beta.1" }
dcrypt-api = { path = "../api", version = "=0.11.0-beta.1" }

[dev-dependencies]
rand = { version = "0.8.5" }

[package.metadata.release]
publish = true
```

## Internal Crate: crates/hybrid/Cargo.toml

```toml
[package]
name = "dcrypt-hybrid"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Hybrid cryptography schemes for the dcrypt library"
repository.workspace = true
license.workspace = true
publish = true

[features]
default = ["std"]
std = [
    "dcrypt-api/std", 
    "dcrypt-common/std", 
    "dcrypt-internal/std"
]
no_std = [
    "dcrypt-api/no_std", 
    "dcrypt-common/no_std", 
    "dcrypt-internal/no_std"
]
serde = [
    "dep:serde", 
    "dcrypt-api/serde", 
    "dcrypt-common/serde"
]


[dependencies]
dcrypt-api = { path = "../api", version = "=0.11.0-beta.1", default-features = false }
dcrypt-common = { path = "../common", version = "=0.11.0-beta.1", default-features = false }
dcrypt-internal = { path = "../internal", version = "=0.11.0-beta.1", default-features = false }
dcrypt-params = { path = "../params", version = "=0.11.0-beta.1" }
dcrypt-algorithms = { path = "../algorithms", version = "=0.11.0-beta.1" }
dcrypt-kem = { path = "../kem", version = "=0.11.0-beta.1" }
dcrypt-sign = { path = "../sign", version = "=0.11.0-beta.1" }
zeroize = { workspace = true }
rand = { workspace = true }
serde = { workspace = true, optional = true }

[dev-dependencies]
rand_chacha = { workspace = true }

[package.metadata.release]
publish = true
```

## Internal Crate: crates/internal/Cargo.toml

```toml
[package]
name = "dcrypt-internal"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Internal utilities for the dcrypt library"
repository.workspace = true
license.workspace = true
publish = true 

[features]
default = ["std"]
std = ["thiserror", "zeroize/std", "alloc"]
alloc = []
no_std = []
simd = []

[dependencies]
zeroize = { version = "1.5.7", features = ["zeroize_derive"] }
thiserror = { version = "1.0.37", optional = true }
subtle = { version = "2.4.1" }

[dev-dependencies]
rand = { version = "0.8.5" }

[package.metadata.release]
publish = true
```

## Internal Crate: crates/kem/Cargo.toml

```toml
[package]
name = "dcrypt-kem"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Key Encapsulation Mechanisms for the dcrypt library"
repository.workspace = true
license.workspace = true
publish = true

[features]
default = ["std"]
std = [
    "dcrypt-api/std", 
    "dcrypt-common/std", 
    "dcrypt-internal/std",
    "alloc"
]
no_std = [
    "dcrypt-api/no_std", 
    "dcrypt-common/no_std", 
    "dcrypt-internal/no_std",
    "alloc"
]
alloc = []
serde = [
    "dep:serde", 
    "dcrypt-api/serde", 
    "dcrypt-common/serde"
]

traditional = []  # Feature flag for traditional KEMs (ECDH, RSA, etc.)
post-quantum = [] # Feature flag for post-quantum KEMs (Kyber, McEliece, etc.)

[dependencies]
dcrypt-api = { path = "../api", version = "=0.11.0-beta.1", default-features = false }
dcrypt-common = { path = "../common", version = "=0.11.0-beta.1", default-features = false }
dcrypt-internal = { path = "../internal", version = "=0.11.0-beta.1", default-features = false }
dcrypt-params = { path = "../params", version = "=0.11.0-beta.1" }
dcrypt-algorithms = { path = "../algorithms", version = "=0.11.0-beta.1" }
zeroize = { workspace = true }
rand = { workspace = true }
serde = { workspace = true, optional = true }
subtle = { version = "2.6.1", default-features = false }

[dev-dependencies]
rand_chacha = { workspace = true }
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "kyber"
harness = false

[[bench]]
name = "ecdh_p192"
harness = false

[[bench]]
name = "ecdh_p224"
harness = false

[[bench]]
name = "ecdh_p256"
harness = false

[[bench]]
name = "ecdh_p384"
harness = false

[[bench]]
name = "ecdh_p521"
harness = false

[[bench]]
name = "ecdh_k256"
harness = false

[[bench]]
name = "ecdh_b283k"
harness = false

[[bench]]
name = "ecdh_comparison"
harness = false

[package.metadata.release]
publish = true
```

## Internal Crate: crates/params/Cargo.toml

```toml
[package]
name = "dcrypt-params"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Constant values for dcrypt library"
repository.workspace = true
license.workspace = true
publish = true


[package.metadata.release]
publish = true
```

## Internal Crate: crates/pke/Cargo.toml

```toml
[package]
name = "dcrypt-pke"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Public Key Encryption schemes for the dcrypt library"
repository.workspace = true
license.workspace = true
publish = true


[features]
default = ["std"]
std = [
    "dcrypt-api/std",
    "dcrypt-common/std",
    "dcrypt-algorithms/std",
    "dep:thiserror",
    "alloc"          # The 'std' feature of 'pke' also implies 'alloc'
]
alloc = [
    "dcrypt-api/alloc",
    "dcrypt-common/alloc",
    "dcrypt-algorithms/alloc",
    # NO 'dep:alloc' here. The features above will trigger alloc usage in those deps.
]
no_std = [
    "dcrypt-api/no_std",
    "dcrypt-common/no_std",
    # As before, no "algorithms/no_std"
]

[dependencies]
dcrypt-api = { path = "../api", version = "=0.11.0-beta.1", default-features = false }
dcrypt-common = { path = "../common", version = "=0.11.0-beta.1", default-features = false }
dcrypt-algorithms = { path = "../algorithms", version = "=0.11.0-beta.1", default-features = false, features = ["ec", "kdf", "aead", "hash"] }
dcrypt-internal = { path = "../internal", version = "=0.11.0-beta.1", default-features = false }
dcrypt-params = { path = "../params", version = "=0.11.0-beta.1" }
rand = { workspace = true, default-features = false }
zeroize = { workspace = true }
subtle = { workspace = true, default-features = false }

thiserror = { workspace = true, optional = true }
# REMOVED: alloc = { package = "alloc", version = "1.0.0", optional = true }


[dev-dependencies]
hex = "0.4"
rand_chacha = { workspace = true }

[package.metadata.release]
publish = true
```

## Internal Crate: crates/sign/Cargo.toml

```toml
[package]
name = "dcrypt-sign"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Digital Signature Schemes for the DCRYPT library"
repository.workspace = true
license.workspace = true
publish = true


[features]
trace = []
default = ["std"]
std = [
    "dcrypt-api/std", 
    "dcrypt-common/std", 
    "dcrypt-internal/std"
]
no_std = [
    "dcrypt-api/no_std", 
    "dcrypt-common/no_std", 
    "dcrypt-internal/no_std"
]
serde = [
    "dep:serde", 
    "dcrypt-api/serde", 
    "dcrypt-common/serde"
]

traditional = []  # Feature flag for traditional signatures (ECDSA, EdDSA, RSA, etc.)
post-quantum = [] # Feature flag for post-quantum signatures (Dilithium, Falcon, etc.)

[dependencies]
dcrypt-api = { path = "../api", version = "=0.11.0-beta.1", default-features = false }
dcrypt-common = { path = "../common", version = "=0.11.0-beta.1", default-features = false }
dcrypt-internal = { path = "../internal", version = "=0.11.0-beta.1", default-features = false }
dcrypt-params = { path = "../params", version = "=0.11.0-beta.1" }
dcrypt-algorithms = { path = "../algorithms", version = "=0.11.0-beta.1" }
zeroize = { workspace = true }
rand = { workspace = true }
serde = { workspace = true, optional = true }
subtle = "2.5"

[dev-dependencies]
rand_chacha = { workspace = true }
hex = "0.4"
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "dilithium"
harness = false

[package.metadata.release]
publish = true
```

## Internal Crate: crates/symmetric/Cargo.toml

```toml
[package]
name = "dcrypt-symmetric"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Symmetric encryption algorithms for the dcrypt library"
repository.workspace = true
license.workspace = true
publish = true

[features]
default = ["std"]
std = [
    "dcrypt-api/std", 
    "dcrypt-common/std", 
    "dcrypt-internal/std"
]
no_std = [
    "dcrypt-api/no_std", 
    "dcrypt-common/no_std", 
    "dcrypt-internal/no_std"
]
serde = [
    "dep:serde", 
    "dcrypt-api/serde", 
    "dcrypt-common/serde"
]

[dependencies]
dcrypt-api = { path = "../api", version = "=0.11.0-beta.1", default-features = false }
dcrypt-common = { path = "../common", version = "=0.11.0-beta.1", default-features = false }
dcrypt-internal = { path = "../internal", version = "=0.11.0-beta.1", default-features = false }
dcrypt-params = { path = "../params", version = "=0.11.0-beta.1" }
dcrypt-algorithms = { path = "../algorithms", version = "=0.11.0-beta.1" }
zeroize = { workspace = true }
serde = { workspace = true, optional = true }
base64 = "0.13"
hmac = "0.12"
pbkdf2 = "0.11"
sha2 = "0.10"
rand = { workspace = true }
hkdf = "0.12"  # Add this missing dependency
byteorder = "1.4"  # Make sure this is included 
subtle = "2.4"   # Make sure constant-time comparison is available

[dev-dependencies]

[package.metadata.release]
publish = true
```

## Internal Crate: crates/utils/Cargo.toml

```toml
[package]
name = "dcrypt-utils"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Utilities and helpers for the DCRYPT library"
repository.workspace = true
license.workspace = true
publish = true

[features]
default = ["std"]
std = [
    "dcrypt-api/std", 
    "dcrypt-common/std", 
    "dcrypt-internal/std"
]
no_std = ["alloc",  # no_std typically needs alloc for Vec, String, etc.
    "dcrypt-api/no_std", 
    "dcrypt-common/no_std", 
    "dcrypt-internal/no_std"
]
alloc = []  # Feature for allocation support in no_std environments

[dependencies]
dcrypt-api = { path = "../api", version = "=0.11.0-beta.1" }
dcrypt-common = { path = "../common", version = "=0.11.0-beta.1" }
dcrypt-internal = { path = "../internal", version = "=0.11.0-beta.1" }
zeroize = { workspace = true }
rand = { workspace = true }
hex = "0.4.3"
base64 = "0.22.1" 

[package.metadata.release]
publish = true
```

## Crate: tests/Cargo.toml

```toml
[package]
name = "dcrypt-tests"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Testing utilities and benchmarks for the DCRYPT library"
repository.workspace = true
license.workspace = true

[dependencies]
dcrypt-kem = { path = "../crates/kem", version = "=0.11.0-beta.1" }
dcrypt-sign = { path = "../crates/sign", version = "=0.11.0-beta.1" }
dcrypt-algorithms = { path = "../crates/algorithms", version = "=0.11.0-beta.1" }
dcrypt-params = { path = "../crates/params", version = "=0.11.0-beta.1" }
dcrypt-symmetric = { path = "../crates/symmetric", version = "=0.11.0-beta.1" }
dcrypt-hybrid = { path = "../crates/hybrid", version = "=0.11.0-beta.1" }
dcrypt-api = { version = "=0.11.0-beta.1", path = "../crates/api" }
dcrypt-common = { path = "../crates/common" , version = "=0.11.0-beta.1" }
dcrypt-internal = { path = "../crates/internal" , version = "=0.11.0-beta.1" }
rand = { workspace = true }
rand_chacha = { workspace = true }
statrs = "0.16"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
once_cell = "1"
hex = "0.4"
thiserror = "1"
arrayref = "0.3"
subtle = "2"
zeroize = { version = "1", features = ["derive"] }
base64 = "0.22"

[dev-dependencies]
proptest = "1"
criterion = { version = "0.5", features = ["html_reports"] }

[build-dependencies]
serde = { version = "1", features = ["derive"] }
toml = "0.8"

[[bench]]
name = "aes_bench"
harness = false

[package.metadata.release]
publish = false
```

## Summary

* Total Cargo.toml files: 13
* Internal crates: 11

### Workspace Members
```
members = [
    "crates/api",
    "crates/common",
    "crates/internal",
    "crates/params",       
    "crates/algorithms", 
    "crates/symmetric",
    "crates/kem",
    "crates/sign",
    "crates/hybrid",
    "crates/pke",
    "crates/utils",
    "tests"
]
```

---
Snapshot generated on Sat Jul 26 01:56:36 PM EDT 2025
