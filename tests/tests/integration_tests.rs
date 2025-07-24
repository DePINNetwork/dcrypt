// Import specific functions from internal crate
use dcrypt_internal::zeroing::secure_zero;
use dcrypt_internal::{ct_eq, ct_select};

// Import math functions from common crate
use dcrypt_common::math_common::{gcd, mod_exp, mod_inv};

// Import types and traits from api crate
use dcrypt_api::{Key, Serialize};

#[test]
fn test_constant_time_compare() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    let c = [1u8, 2, 3, 5];

    assert!(ct_eq(&a, &b));
    assert!(!ct_eq(&a, &c));
    assert!(!ct_eq(&a, &a[..3]));
}

#[test]
fn test_constant_time_select() {
    assert_eq!(ct_select(1, 2, false), 1);
    assert_eq!(ct_select(1, 2, true), 2);
}

#[test]
fn test_secure_zeroing() {
    let mut data = vec![1u8, 2, 3, 4];
    secure_zero(&mut data);

    assert_eq!(data, vec![0u8, 0, 0, 0]);
}

#[test]
fn test_modular_exponentiation() {
    assert_eq!(mod_exp(2, 10, 1000), 24); // 2^10 mod 1000 = 1024 mod 1000 = 24
    assert_eq!(mod_exp(3, 4, 10), 1); // 3^4 mod 10 = 81 mod 10 = 1
}

#[test]
fn test_gcd() {
    assert_eq!(gcd(12, 8), 4);
    assert_eq!(gcd(17, 13), 1);
    assert_eq!(gcd(0, 5), 5);
    assert_eq!(gcd(5, 0), 5);
}

#[test]
fn test_mod_inv() {
    // 3 * 5 ≡ 1 (mod 14)
    assert_eq!(mod_inv(3, 14), Some(5));

    // 7 * 8 ≡ 1 (mod 15)
    assert_eq!(mod_inv(7, 15), Some(13));

    // No inverse exists when gcd(a, m) != 1
    assert_eq!(mod_inv(4, 8), None);
}

#[test]
fn test_key_serialization() {
    let key = Key::new(&[1, 2, 3, 4]);
    let bytes = key.to_bytes().unwrap();
    let recovered_key = Key::from_bytes(&bytes).unwrap();

    assert_eq!(key.as_ref(), recovered_key.as_ref());
}
