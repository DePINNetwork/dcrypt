//! Common mathematical operations for cryptographic algorithms

/// Perform modular exponentiation (a^b mod m)
///
/// Implements the square-and-multiply algorithm for efficient
/// modular exponentiation.
pub fn mod_exp(a: u64, b: u64, m: u64) -> u64 {
    if m == 1 {
        return 0;
    }

    let mut result = 1;
    let mut base = a % m;
    let mut exp = b;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % m;
        }

        exp >>= 1;
        base = (base * base) % m;
    }

    result
}

/// Compute the greatest common divisor of two numbers
pub fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        return a;
    }

    gcd(b, a % b)
}

/// Extended Euclidean algorithm to compute a^(-1) mod m
pub fn mod_inv(a: u64, m: u64) -> Option<u64> {
    if m == 0 || m == 1 {
        return None; // No modular inverse exists
    }

    // Ensure a is within the range [1, m-1]
    let a = a % m;
    if a == 0 {
        return None; // No modular inverse exists for 0
    }

    // Initialize variables for the extended Euclidean algorithm
    let mut a = a as i64;
    let m_orig = m as i64;
    let mut m = m_orig;

    let mut x0: i64 = 1;
    let mut x1: i64 = 0;

    // Apply the extended Euclidean algorithm
    while a > 1 {
        if m == 0 {
            return None; // No modular inverse exists (not coprime)
        }

        let q = a / m;
        let temp = m;

        m = a % m;
        a = temp;

        let temp = x1;
        x1 = x0 - q * x1;
        x0 = temp;
    }

    // Ensure the result is positive
    if x0 < 0 {
        x0 += m_orig;
    }

    if a == 1 {
        Some(x0 as u64)
    } else {
        // No modular inverse exists
        None
    }
}

/// Perform modular addition: (a + b) mod m
pub fn mod_add(a: u64, b: u64, m: u64) -> u64 {
    (a + b) % m
}

/// Perform modular subtraction: (a - b) mod m
pub fn mod_sub(a: u64, b: u64, m: u64) -> u64 {
    (a + m - (b % m)) % m
}

/// Perform modular multiplication: (a * b) mod m
pub fn mod_mul(a: u64, b: u64, m: u64) -> u64 {
    (a * b) % m
}
