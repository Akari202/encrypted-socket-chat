mod constants;
pub mod point;
pub mod prime;
use num::{BigInt, BigUint, Signed};
use more_asserts as ma;

pub fn modular_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let mut exponent = exponent.clone();
    if modulus == &BigUint::from(1u8) {
        BigUint::ZERO
    }
    else {
        let mut result = BigUint::from(1u8);
        let mut base = base % modulus;
        let one = BigUint::from(1u8);
        let two = &BigUint::from(2u8);
        while exponent > BigUint::ZERO {
            if &exponent % two == one {
                result = result * &base % modulus;
            }
            exponent >>= 1;
            base = &base * &base % modulus;
        }
        result
    }
}

pub fn xgcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let mut a = a.clone();
    let mut b = b.clone();
    let mut x0 = BigInt::from(1u8);
    let mut x1 = BigInt::ZERO;
    let mut y0 = BigInt::ZERO;
    let mut y1 = BigInt::from(1u8);
    while b > BigInt::ZERO {
        let q = &a / &b;
        let r = &a % &b;
        let x0_old = x0;
        x0 = x1.clone();
        x1 = x0_old - &q * x1;
        let y0_old = y0;
        y0 = y1.clone();
        y1 = y0_old - &q * y1;

        a = b.clone();
        b = r;
    }
    (a.clone(), x0.clone(), y0.clone())
}

pub fn modular_inverse(e: &BigInt, phi: &BigInt) -> BigUint {
    let mut e = e.clone();
    while e < BigInt::ZERO {
        e += phi
    }
    let (_, _, y) = xgcd(phi, &e);
    let mut inverse = y % phi;
    while inverse < BigInt::ZERO {
        inverse += phi;
    }
    ma::assert_ge!(inverse, BigInt::ZERO);
    inverse.to_biguint().unwrap()
}

