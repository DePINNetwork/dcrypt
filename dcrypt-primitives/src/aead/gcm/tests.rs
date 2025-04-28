use super::*;
use crate::block::aes::{Aes128, Aes192, Aes256};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[test]
fn test_aes_gcm() {
    // Basic sanity vector (128-bit key, 96-bit nonce, full tag)
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
    let plaintext = hex::decode(
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
    )
    .unwrap();
    let expected_full = hex::decode(
        "42831ec2217774244b7221b784d0d49c\
         e3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa05\
         1ba30b396a0aac973d58e0915bc94fbc\
         3221a5db94fae95ae7121a47",
    )
    .unwrap();

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let ct = gcm.internal_encrypt(&plaintext, Some(&aad)).unwrap();
    assert_eq!(ct.len(), expected_full.len());
    assert_eq!(hex::encode(&ct), hex::encode(&expected_full));

    // Round-trip
    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let pt = gcm.internal_decrypt(&ct, Some(&aad)).unwrap();
    assert_eq!(pt, plaintext);
}


#[test]
fn test_gcm_tampered_ciphertext() {
    let key = [0x42; 16];
    let nonce = [0x24; 12];
    let aad = [0x10; 16];
    let plaintext = [0xAA; 32];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();

    let mut ciphertext = gcm.internal_encrypt(&plaintext, Some(&aad)).unwrap();
    if ciphertext.len() > 5 {
        ciphertext[5] ^= 0x01;
    }

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let result = gcm.internal_decrypt(&ciphertext, Some(&aad));
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::AuthenticationFailed)));
}

#[test]
fn test_gcm_tampered_tag() {
    let key = [0x42; 16];
    let nonce = [0x24; 12];
    let plaintext = [0xAA; 32];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();

    let mut ciphertext = gcm.internal_encrypt(&plaintext, None).unwrap();
    let tag_len = GCM_TAG_SIZE;
    if ciphertext.len() >= tag_len {
        let tag_idx = ciphertext.len() - tag_len;
        ciphertext[tag_idx] ^= 0x01;
    }

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let result = gcm.internal_decrypt(&ciphertext, None);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::AuthenticationFailed)));
}

#[test]
fn test_gcm_empty_plaintext() {
    let key = [0x42; 16];
    let nonce = [0x24; 12];
    let aad = [0x10; 16];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();

    let ciphertext = gcm.internal_encrypt(&[], Some(&aad)).unwrap();
    assert_eq!(ciphertext.len(), GCM_TAG_SIZE);

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let decrypted = gcm.internal_decrypt(&ciphertext, Some(&aad)).unwrap();
    assert_eq!(decrypted.len(), 0);
}

#[test]
fn test_gcm_invalid_nonce() {
    let key = [0x42; 16];
    let empty_nonce: [u8; 0] = [];
    let long_nonce = [0x24; 17];
    let cipher = Aes128::new(&key);

    let result = Gcm::new(cipher.clone(), &empty_nonce);
    assert!(result.is_err());

    let result = Gcm::new(cipher, &long_nonce);
    assert!(result.is_err());
}

#[test]
fn test_gcm_short_ciphertext() {
    let key = [0x42; 16];
    let nonce = [0x24; 12];
    let ciphertext = [0xAA; 8];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let result = gcm.internal_decrypt(&ciphertext, None);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidLength { .. })));
}

#[test]
fn test_gcm_empty_associated_data() {
    let key = [0x42; 16];
    let nonce = [0x24; 12];
    let plaintext = [0xAA; 32];
    let empty_aad: [u8; 0] = [];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let ciphertext = gcm.internal_encrypt(&plaintext, Some(&empty_aad)).unwrap();

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let decrypted = gcm.internal_decrypt(&ciphertext, Some(&empty_aad)).unwrap();
    assert_eq!(decrypted, plaintext);

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let decrypted = gcm.internal_decrypt(&ciphertext, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_gcm_non_standard_nonce() {
    let key = [0x42; 16];
    let nonce = [0x24; 8];
    let plaintext = [0xAA; 32];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let ciphertext = gcm.internal_encrypt(&plaintext, None).unwrap();

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher, &nonce).unwrap();
    let decrypted = gcm.internal_decrypt(&ciphertext, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

// -------------------------------------------------------------------------
// NIST CAVP Test Vector Parser & Runner
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct GcmTestVector {
    key: Vec<u8>,
    iv: Vec<u8>,
    pt: Option<Vec<u8>>,
    ct: Option<Vec<u8>>,
    aad: Vec<u8>,
    tag: Vec<u8>,
    fail_expected: bool,
}

struct GcmTestGroup {
    key_len: usize,
    iv_len: usize,
    pt_len: usize,
    aad_len: usize,
    tag_len: usize,
    test_vectors: Vec<GcmTestVector>,
}

fn parse_gcm_test_file(filepath: &str) -> Vec<GcmTestGroup> {
    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut groups = Vec::new();
    let mut current: Option<GcmTestGroup> = None;
    let mut vector: Option<GcmTestVector> = None;

    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let p = &line[1..line.len() - 1];
            let parts: Vec<&str> = p.split('=').collect();
            if parts.len() == 2 {
                let name = parts[0].trim();
                let val = parts[1].trim().parse().unwrap_or(0);
                match name {
                    "Keylen" => {
                        if let Some(g) = current.take() {
                            groups.push(g);
                        }
                        current = Some(GcmTestGroup {
                            key_len: val,
                            iv_len: 0,
                            pt_len: 0,
                            aad_len: 0,
                            tag_len: 0,
                            test_vectors: Vec::new(),
                        });
                    }
                    "IVlen" => current.as_mut().unwrap().iv_len = val,
                    "PTlen" => current.as_mut().unwrap().pt_len = val,
                    "AADlen" => current.as_mut().unwrap().aad_len = val,
                    "Taglen" => current.as_mut().unwrap().tag_len = val,
                    _ => {}
                }
            }
            continue;
        }
        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() == 2 {
            let name = parts[0].trim();
            let val = parts[1].trim();
            match name {
                "Count" => {
                    if let Some(v) = vector.take() {
                        current.as_mut().unwrap().test_vectors.push(v);
                    }
                    vector = Some(GcmTestVector {
                        key: Vec::new(),
                        iv: Vec::new(),
                        pt: None,
                        ct: None,
                        aad: Vec::new(),
                        tag: Vec::new(),
                        fail_expected: false,
                    });
                }
                "Key" => vector.as_mut().unwrap().key = hex::decode(val).unwrap(),
                "IV" => vector.as_mut().unwrap().iv = hex::decode(val).unwrap(),
                "PT" => vector.as_mut().unwrap().pt = Some(hex::decode(val).unwrap()),
                "CT" => vector.as_mut().unwrap().ct = Some(hex::decode(val).unwrap()),
                "AAD" => vector.as_mut().unwrap().aad = hex::decode(val).unwrap(),
                "Tag" => vector.as_mut().unwrap().tag = hex::decode(val).unwrap(),
                "FAIL" => vector.as_mut().unwrap().fail_expected = true,
                _ => {}
            }
        }
    }
    if let Some(v) = vector {
        current.as_mut().unwrap().test_vectors.push(v);
    }
    if let Some(g) = current {
        groups.push(g);
    }
    groups
}

#[test]
fn test_aes_gcm_nist_decrypt_vectors() {
    let base = env!("CARGO_MANIFEST_DIR");
    let dir = format!("{}/../../dcrypt-test/src/vectors/gcm", base);
    let files = [
        format!("{}/gcmDecrypt128.rsp", dir),
        format!("{}/gcmDecrypt192.rsp", dir),
        format!("{}/gcmDecrypt256.rsp", dir),
    ];
    for f in &files {
        if !Path::new(f).exists() {
            eprintln!("Missing file: {}", f);
            return;
        }
    }
    run_gcm_decrypt_tests::<Aes128>(&files[0]);
    run_gcm_decrypt_tests::<Aes192>(&files[1]);
    run_gcm_decrypt_tests::<Aes256>(&files[2]);
}

#[test]
fn test_aes_gcm_nist_encrypt_vectors() {
    let base = env!("CARGO_MANIFEST_DIR");
    let dir = format!("{}/../../dcrypt-test/src/vectors/gcm", base);
    let files = [
        format!("{}/gcmEncryptExtIV128.rsp", dir),
        format!("{}/gcmEncryptExtIV192.rsp", dir),
        format!("{}/gcmEncryptExtIV256.rsp", dir),
    ];
    for f in &files {
        if !Path::new(f).exists() {
            eprintln!("Missing file: {}", f);
            return;
        }
    }
    run_gcm_encrypt_tests::<Aes128>(&files[0]);
    run_gcm_encrypt_tests::<Aes192>(&files[1]);
    run_gcm_encrypt_tests::<Aes256>(&files[2]);
}

fn run_gcm_decrypt_tests<B: BlockCipher>(filepath: &str) {
    let groups = parse_gcm_test_file(filepath);
    for group in groups {
        for (i, test) in group.test_vectors.iter().enumerate() {
            let cipher = B::new(&test.key);
            let tag_bytes = group.tag_len / 8;
            let gcm = Gcm::new_with_tag_len(cipher, &test.iv, tag_bytes)
                .expect("GCM ctor failed");
            let mut cw = Vec::new();
            if let Some(ref ct) = test.ct {
                cw.extend_from_slice(ct);
            }
            cw.extend_from_slice(&test.tag);
            let aad = if test.aad.is_empty() {
                None
            } else {
                Some(&test.aad[..])
            };
            let res = gcm.internal_decrypt(&cw, aad);
            if test.fail_expected {
                assert!(res.is_err(), "Vector {} should fail", i);
            } else {
                let pt = res.expect(&format!("Decrypt failed at {}", i));
                if let Some(ref expected) = test.pt {
                    assert_eq!(pt, *expected, "PT mismatch at {}", i);
                }
            }
        }
    }
}

fn run_gcm_encrypt_tests<B: BlockCipher>(filepath: &str) {
    let groups = parse_gcm_test_file(filepath);
    for group in groups {
        for (i, test) in group.test_vectors.iter().enumerate() {
            println!("Running encrypt test case {}", i);
            let cipher = B::new(&test.key);
            // use default 16‐byte tag for all NIST vectors
            let gcm = Gcm::new(cipher, &test.iv).unwrap();

            let plaintext = test.pt.as_ref().map_or(&[][..], |v| &v[..]);
            let aad = if test.aad.is_empty() {
                None
            } else {
                Some(&test.aad[..])
            };

            let cw = gcm.internal_encrypt(plaintext, aad).unwrap();

            // split off ciphertext vs. tag by expected lengths
            let exp_ct_len = test.ct.as_ref().map_or(0, |v| v.len());
            let exp_tag_len = test.tag.len();
            assert_eq!(
                cw.len(),
                exp_ct_len + exp_tag_len,
                "Length mismatch for test case {}",
                i
            );

            let (ct, tag) = cw.split_at(exp_ct_len);
            if let Some(ref expected_ct) = test.ct {
                assert_eq!(
                    ct,
                    expected_ct.as_slice(),
                    "Ciphertext mismatch at case {}",
                    i
                );
            }
            assert_eq!(
                tag,
                test.tag.as_slice(),
                "Authentication tag mismatch for case {}",
                i
            );
        }
    }
}