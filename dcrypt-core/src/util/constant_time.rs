//! Constant-time operations to prevent timing attacks

use subtle::{ConstantTimeEq, Choice, ConditionallySelectable};

/// Constant-time comparison of two byte slices
///
/// Returns true if the slices are equal, false otherwise.
/// This function runs in constant time regardless of the input values.
pub fn ct_eq<A, B>(a: A, b: B) -> bool
where
    A: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let a = a.as_ref();
    let b = b.as_ref();

    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

/// Constant-time selection of a byte
///
/// Returns `a` if `condition` is false, `b` if `condition` is true.
/// This function runs in constant time regardless of the input values.
pub fn ct_select(a: u8, b: u8, condition: bool) -> u8 {
    let choice = Choice::from(condition as u8);
    u8::conditional_select(&a, &b, choice)
}

/// Constant-time conditional assignment
///
/// Sets `dst` to `src` if `condition` is true, otherwise leaves `dst` unchanged.
/// This function runs in constant time regardless of the input values.
pub fn ct_assign(dst: &mut [u8], src: &[u8], condition: bool) {
    assert_eq!(dst.len(), src.len());
    
    let choice = Choice::from(condition as u8);
    
    for i in 0..dst.len() {
        dst[i] = u8::conditional_select(&dst[i], &src[i], choice);
    }
}