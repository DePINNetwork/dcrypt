use super::*;
use hex;

#[test]
fn test_sha1_empty_string() {
    let expected = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    let result = hex::encode(Sha1::digest(b"").unwrap());
    assert_eq!(result, expected);
}

#[test]
fn test_sha1_abc() {
    let expected = "a9993e364706816aba3e25717850c26c9cd0d89d";
    let result = hex::encode(Sha1::digest(b"abc").unwrap());
    assert_eq!(result, expected);
}

#[test]
fn test_sha1_longer_text() {
    let expected = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
    let result = hex::encode(
        Sha1::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").unwrap(),
    );
    assert_eq!(result, expected);
}

#[test]
fn test_sha1_incremental() {
    let mut hasher = Sha1::new();
    hasher.update(b"abc").unwrap();
    hasher.update(b"defghijklmnopqrstuvwxyz").unwrap();
    let result = hex::encode(hasher.finalize().unwrap());
    let expected = "32d10c7b8cf96570ca04ce37f2a19d84240d3a89";
    assert_eq!(result, expected);
}
