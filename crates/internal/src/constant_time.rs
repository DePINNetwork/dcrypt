//! Constant-time operations to prevent timing attacks

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

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
pub fn ct_select<T>(a: T, b: T, condition: bool) -> T
where
    T: ConditionallySelectable,
{
    let choice = Choice::from(condition as u8);
    T::conditional_select(&a, &b, choice)
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

/// Trait for types that can be compared in constant time
pub trait ConstantTimeEquals {
    /// Compare two values in constant time
    fn ct_equals(&self, other: &Self) -> bool;
}

/// Implement ConstantTimeEquals for all types that implement AsRef<[u8]>
impl<T: AsRef<[u8]>> ConstantTimeEquals for T {
    fn ct_equals(&self, other: &Self) -> bool {
        ct_eq(self.as_ref(), other.as_ref())
    }
}

/// Constant-time equality check that returns a Choice (0 or 1)
pub fn ct_eq_choice<A, B>(a: A, b: B) -> Choice
where
    A: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let a = a.as_ref();
    let b = b.as_ref();

    if a.len() != b.len() {
        return Choice::from(0);
    }

    a.ct_eq(b)
}

/// Apply a constant-time bitwise AND operation between two arrays
pub fn ct_and<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] & b[i];
    }
    result
}

/// Apply a constant-time bitwise OR operation between two arrays
pub fn ct_or<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] | b[i];
    }
    result
}

/// Apply a constant-time bitwise XOR operation between two arrays
pub fn ct_xor<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Generic constant-time conditional operation on byte arrays
///
/// Applies the function `op` to elements of `a` and `b` based on the condition.
/// This is useful for implementing constant-time bit operations.
pub fn ct_op<const N: usize, F>(a: &[u8; N], b: &[u8; N], condition: bool, op: F) -> [u8; N]
where
    F: Fn(u8, u8) -> u8,
{
    let choice = Choice::from(condition as u8);
    let mut result = [0u8; N];

    for i in 0..N {
        // If condition is true, apply op(a[i], b[i]), otherwise keep a[i]
        let operated = op(a[i], b[i]);
        result[i] = u8::conditional_select(&a[i], &operated, choice);
    }

    result
}

/// Constant-time mask generation for a boolean condition
///
/// Returns an all-1s mask if condition is true, all-0s if false
pub fn ct_mask(condition: bool) -> u8 {
    0u8.wrapping_sub(condition as u8)
}
