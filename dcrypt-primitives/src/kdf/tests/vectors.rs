//! Test vectors for Key Derivation Functions
//!
//! This module contains standard test vectors for validating the
//! implementations of HKDF, PBKDF2, and Argon2.

use crate::kdf::*;
use crate::hash::{Sha1, Sha256, Sha512};
use hex;

#[test]
fn test_hkdf_rfc5869_vectors() {
    // Test Case 1 from RFC 5869
    #[allow(non_snake_case)]
    let test_case_1 = {
        let IKM = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let L = 42;
        let PRK = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
        let OKM = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();
        (IKM, salt, info, L, PRK, OKM)
    };
    
    // Test extract
    let prk = Hkdf::<Sha256>::extract(Some(&test_case_1.1), &test_case_1.0);
    assert_eq!(prk, test_case_1.4, "HKDF-Extract failed for test case 1");
    
    // Test expand
    let okm = Hkdf::<Sha256>::expand(&prk, Some(&test_case_1.2), test_case_1.3).unwrap();
    assert_eq!(okm, test_case_1.5, "HKDF-Expand failed for test case 1");
    
    // Test Case 2 from RFC 5869
    #[allow(non_snake_case)]
    let test_case_2 = {
        let IKM = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap();
        let salt = hex::decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
        let info = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let L = 82;
        let PRK = hex::decode("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244").unwrap();
        let OKM = hex::decode("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87").unwrap();
        (IKM, salt, info, L, PRK, OKM)
    };
    
    // Test extract
    let prk = Hkdf::<Sha256>::extract(Some(&test_case_2.1), &test_case_2.0);
    assert_eq!(prk, test_case_2.4, "HKDF-Extract failed for test case 2");
    
    // Test expand
    let okm = Hkdf::<Sha256>::expand(&prk, Some(&test_case_2.2), test_case_2.3).unwrap();
    assert_eq!(okm, test_case_2.5, "HKDF-Expand failed for test case 2");
    
    // Test Case 3 from RFC 5869 - SHA-256 with default salt
    #[allow(non_snake_case)]
    let test_case_3 = {
        let IKM = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt: Option<&[u8]> = None;
        let info: Option<&[u8]> = None;
        let L = 42;
        let PRK = hex::decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04").unwrap();
        let OKM = hex::decode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8").unwrap();
        (IKM, salt, info, L, PRK, OKM)
    };
    
    // Test extract
    let prk = Hkdf::<Sha256>::extract(test_case_3.1, &test_case_3.0);
    assert_eq!(prk, test_case_3.4, "HKDF-Extract failed for test case 3");
    
    // Test expand
    let okm = Hkdf::<Sha256>::expand(&prk, test_case_3.2, test_case_3.3).unwrap();
    assert_eq!(okm, test_case_3.5, "HKDF-Expand failed for test case 3");
    
    // Test Case 4 from RFC 5869 - SHA-1
    #[allow(non_snake_case)]
    let test_case_4 = {
        let IKM = hex::decode("0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let L = 42;
        let PRK = hex::decode("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243").unwrap();
        let OKM = hex::decode("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896").unwrap();
        (IKM, salt, info, L, PRK, OKM)
    };
    
    // Test extract
    let prk = Hkdf::<Sha1>::extract(Some(&test_case_4.1), &test_case_4.0);
    assert_eq!(prk, test_case_4.4, "HKDF-Extract failed for test case 4 (SHA-1)");
    
    // Test expand
    let okm = Hkdf::<Sha1>::expand(&prk, Some(&test_case_4.2), test_case_4.3).unwrap();
    assert_eq!(okm, test_case_4.5, "HKDF-Expand failed for test case 4 (SHA-1)");
}

#[test]
fn test_pbkdf2_rfc6070_vectors() {
    // Test Case 1 from RFC 6070
    let test_case_1 = {
        let P = b"password";
        let S = b"salt";
        let c = 1;
        let dkLen = 20;
        let expected = hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6").unwrap();
        (P, S, c, dkLen, expected)
    };
    
    let derived = Pbkdf2::<Sha1>::pbkdf2::<Sha1>(test_case_1.0, test_case_1.1, test_case_1.2, test_case_1.3).unwrap();
    assert_eq!(derived, test_case_1.4, "PBKDF2 failed for test case 1");
    
    // Test Case 2 from RFC 6070
    let test_case_2 = {
        let P = b"password";
        let S = b"salt";
        let c = 2;
        let dkLen = 20;
        let expected = hex::decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957").unwrap();
        (P, S, c, dkLen, expected)
    };
    
    let derived = Pbkdf2::<Sha1>::pbkdf2::<Sha1>(test_case_2.0, test_case_2.1, test_case_2.2, test_case_2.3).unwrap();
    assert_eq!(derived, test_case_2.4, "PBKDF2 failed for test case 2");
    
    // Test Case 3 from RFC 6070
    let test_case_3 = {
        let P = b"password";
        let S = b"salt";
        let c = 4096;
        let dkLen = 20;
        let expected = hex::decode("4b007901b765489abead49d926f721d065a429c1").unwrap();
        (P, S, c, dkLen, expected)
    };
    
    let derived = Pbkdf2::<Sha1>::pbkdf2::<Sha1>(test_case_3.0, test_case_3.1, test_case_3.2, test_case_3.3).unwrap();
    assert_eq!(derived, test_case_3.4, "PBKDF2 failed for test case 3");
    
    // Test Case 5 from RFC 6070 (skipping Case 4 as it takes too long)
    let test_case_5 = {
        let P = b"passwordPASSWORDpassword";
        let S = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
        let c = 4096;
        let dkLen = 25;
        let expected = hex::decode("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038").unwrap();
        (P, S, c, dkLen, expected)
    };
    
    let derived = Pbkdf2::<Sha1>::pbkdf2::<Sha1>(test_case_5.0, test_case_5.1, test_case_5.2, test_case_5.3).unwrap();
    assert_eq!(derived, test_case_5.4, "PBKDF2 failed for test case 5");
    
    // Test Case 6 from RFC 6070
    let test_case_6 = {
        let P = b"pass\0word";
        let S = b"sa\0lt";
        let c = 4096;
        let dkLen = 16;
        let expected = hex::decode("56fa6aa75548099dcc37d7f03425e0c3").unwrap();
        (P, S, c, dkLen, expected)
    };
    
    let derived = Pbkdf2::<Sha1>::pbkdf2::<Sha1>(test_case_6.0, test_case_6.1, test_case_6.2, test_case_6.3).unwrap();
    assert_eq!(derived, test_case_6.4, "PBKDF2 failed for test case 6");
}

#[test]
fn test_argon2_reference_vectors() {
    // Test vectors for Argon2i from the reference implementation
    let test_vectors_i = [
        // (password, salt, t_cost, m_cost, parallelism, output_len, expected_hex)
        (
            b"password" as &[u8],
            b"somesalt" as &[u8],
            1u32,
            64u32,
            1u32,
            32usize,
            "e9c902074ccf5a179bef212b7080d61bdacd16af2b92eac82f91cdcc2afa3e6a"
        ),
        (
            b"password",
            b"somesalt",
            2,
            64,
            1,
            32,
            "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
        ),
        (
            b"password",
            b"somesalt",
            2,
            256,
            1,
            32,
            "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f"
        ),
    ];
    
    for (i, &(password, salt, t_cost, m_cost, parallelism, output_len, expected_hex)) in test_vectors_i.iter().enumerate() {
        let params = Argon2Params {
            argon_type: Argon2Type::Argon2i,
            time_cost: t_cost,
            memory_cost: m_cost,
            parallelism,
            salt: salt.to_vec(),
            ad: None,
            output_len,
        };
        
        let argon2 = Argon2::new_with_params(params);
        let result = argon2.hash_password(password).unwrap();
        let expected = hex::decode(expected_hex).unwrap();
        
        assert_eq!(result, expected, "Argon2i test vector {} failed", i);
    }
    
    // Test vectors for Argon2d from the reference implementation
    let test_vectors_d = [
        // (password, salt, t_cost, m_cost, parallelism, output_len, expected_hex)
        (
            b"password" as &[u8],
            b"somesalt" as &[u8],
            1u32,
            64u32,
            1u32,
            32usize,
            "9443c0c9aaee91dbf15f69cf728ec3a3fa788160a8a18c4c627b299f1e171c78"
        ),
        (
            b"password",
            b"somesalt",
            2,
            64,
            1,
            32,
            "98fdd9e2da3f50e99c59603193dd73d7d0dd98dfd9253bb61f1ad2c65a3c1c89"
        ),
        (
            b"password",
            b"somesalt",
            2,
            256,
            1,
            32,
            "8839176b284eb49d210e7ab7656d6e202b5f9e36b86f9d3e88d6f5824e58a1e7"
        ),
    ];
    
    for (i, &(password, salt, t_cost, m_cost, parallelism, output_len, expected_hex)) in test_vectors_d.iter().enumerate() {
        let params = Argon2Params {
            argon_type: Argon2Type::Argon2d,
            time_cost: t_cost,
            memory_cost: m_cost,
            parallelism,
            salt: salt.to_vec(),
            ad: None,
            output_len,
        };
        
        let argon2 = Argon2::new_with_params(params);
        let result = argon2.hash_password(password).unwrap();
        let expected = hex::decode(expected_hex).unwrap();
        
        assert_eq!(result, expected, "Argon2d test vector {} failed", i);
    }
}

#[test]
fn test_kdf_edge_cases() {
    // Test HKDF with very small outputs
    let small_output = Hkdf::<Sha256>::derive(Some(b"salt"), b"input", None, 1).unwrap();
    assert_eq!(small_output.len(), 1);
    
    // Test HKDF with max allowed output
    let max_output_len = 255 * Sha256::output_size();
    let large_output = Hkdf::<Sha256>::derive(Some(b"salt"), b"input", None, max_output_len).unwrap();
    assert_eq!(large_output.len(), max_output_len);
    
    // Test PBKDF2 with small outputs
    let pbkdf2_small = Pbkdf2::<Sha256>::pbkdf2::<Sha256>(b"pass", b"salt", 1, 1).unwrap();
    assert_eq!(pbkdf2_small.len(), 1);
    
    // Test Argon2 with minimum parameters
    let params = Argon2Params {
        argon_type: Argon2Type::Argon2i,
        memory_cost: 8,      // Minimum allowed = 8 * parallelism
        time_cost: 1,        // Minimum allowed
        parallelism: 1,      // Minimum allowed
        salt: b"salt".to_vec(),
        ad: None,
        output_len: 4,       // Minimum allowed
    };
    
    let argon2 = Argon2::new_with_params(params);
    let result = argon2.hash_password(b"password").unwrap();
    assert_eq!(result.len(), 4);
}