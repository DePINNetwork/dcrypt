// tests/acvp_tests.rs
use tests::suites::acvp::{loader, runner::Runner, engine::DcryptEngine};

#[test]
fn test_aes_cbc_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ACVP-AES-CBC-1.0")
        .expect("Failed to load ACVP-AES-CBC-1.0 suite");
    
    let r = Runner::new(&engine);
    
    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("ACVP tests failed");
}

#[test]
fn test_aes_ctr_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ACVP-AES-CTR-1.0")
        .expect("Failed to load ACVP-AES-CTR-1.0 suite");
    
    // DEBUG: Print what's actually in the group defaults
    // println!("DEBUG ▶ first-group defaults = {:#?}", suite.groups[0].defaults);
    
    // DEBUG: Print what's in the first test case
    // println!("DEBUG ▶ first test raw = {:#?}", suite.groups[0].tests[0].inputs);
    
    let r = Runner::new(&engine);
    
    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("ACVP tests failed");
}

#[test]
fn test_aes_gcm_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ACVP-AES-GCM-1.0")
        .expect("Failed to load ACVP-AES-GCM-1.0 suite");
    
    let r = Runner::new(&engine);
    
    println!("Running ACVP test suite: {}", suite.suite_name);
    // println!("Number of test groups: {}", suite.groups.len());
    
    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     if let Some(direction) = &first_group.direction {
    //         println!("First group direction: {}", direction);
    //     }
        
    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }
    
    // Run the test suite
    r.run_suite(&suite).expect("ACVP GCM tests failed");
}

#[test]
fn test_ecdsa_keygen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ECDSA-KeyGen-FIPS186-5")
        .expect("Failed to load ECDSA-KeyGen-FIPS186-5 suite");
    
    let r = Runner::new(&engine);
    
    println!("Running ACVP test suite: ECDSA-KeyGen-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());
    
    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);
        
    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }
    
    r.run_suite(&suite).expect("ACVP ECDSA KeyGen tests failed");
}

#[test]
fn test_ecdsa_keyver_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ECDSA-KeyVer-FIPS186-5")
        .expect("Failed to load ECDSA-KeyVer-FIPS186-5 suite");
    
    let r = Runner::new(&engine);
    
    println!("Running ACVP test suite: ECDSA-KeyVer-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());
    
    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);
        
    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }
    
    r.run_suite(&suite).expect("ACVP ECDSA KeyVer tests failed");
}

#[test]
fn test_ecdsa_siggen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ECDSA-SigGen-FIPS186-5")
        .expect("Failed to load ECDSA-SigGen-FIPS186-5 suite");
    
    let r = Runner::new(&engine);
    
    println!("Running ACVP test suite: ECDSA-SigGen-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());
    
    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);
        
    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }
    
    r.run_suite(&suite).expect("ACVP ECDSA SigGen tests failed");
}

#[test]
fn test_ecdsa_sigver_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ECDSA-SigVer-FIPS186-5")
        .expect("Failed to load ECDSA-SigVer-FIPS186-5 suite");
    
    let r = Runner::new(&engine);
    
    println!("Running ACVP test suite: ECDSA-SigVer-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());
    
    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);
        
    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }
    
    r.run_suite(&suite).expect("ACVP ECDSA SigVer tests failed");
}

#[test]
fn test_ml_kem_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-KEM-encapDecap-FIPS203")
        .expect("Failed to load ML-KEM-encapDecap-FIPS203 suite");
    
    let r = Runner::new(&engine);
    
    println!("Running ACVP test suite: ML-KEM-encapDecap-FIPS203");
    // println!("Number of test groups: {}", suite.groups.len());
    
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type); // Should be "AFT"
    //     // For KEMs, the "direction" is more like a "function"
    //     if let Some(function) = first_group.defaults.get("function").map(|v| v.as_string()) {
    //          println!("First group function: {}", function);
    //     } else if let Some(function) = first_group.direction.as_ref() {
    //         println!("First group function (from direction): {}", function);
    //     }
    //      println!("First group parameterSet: {:?}", first_group.defaults.get("parameterSet").map(|v| v.as_string()));


    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }
    
    r.run_suite(&suite).expect("ACVP ML-KEM tests failed");
}

#[test]
fn test_ml_kem_keygen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-KEM-keyGen-FIPS203")
        .expect("Failed to load ML-KEM-keyGen-FIPS203 suite");
    
    let r = Runner::new(&engine);
    
    println!("Running ACVP test suite: ML-KEM-keyGen-FIPS203");
    r.run_suite(&suite).expect("ACVP ML-KEM keyGen tests failed");
}

#[test]
fn full_stack_sha256_suite() {
    let engine = DcryptEngine;
    let suites = loader::load_all_suites();
    let r = Runner::new(&engine);

    // SHA-256 tests would need to be loaded separately
    // For now, this test is disabled as we're focusing on AES-CBC
    
    /*
    let sha256 = suites.iter()
        .find(|s| s.suite_name.contains("SHA2-256"))
        .expect("suite not found");

    r.run_suite(sha256).unwrap();
    */
}
