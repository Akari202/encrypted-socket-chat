use num::bigint::ToBigInt;
use num::BigInt;
use num::Signed;
use num::BigUint;
use more_asserts as ma;

use super::modular_inverse;

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone)]
pub struct Point {
    x: BigInt,
    y: BigInt
}

impl Point {
    pub fn new(x: BigInt, y: BigInt) -> Self {
        Self {
            x,
            y
        }
    }

    pub fn new_usize(x: usize, y: usize) -> Self {
        Self::new(BigInt::from(x), BigInt::from(y))
    }

    pub fn point_addition(lhs: &Point, rhs: &Point, q: &BigUint, a: &BigInt) -> Self {
        let q = &q.to_bigint().unwrap();
        let mut lambda = if lhs == rhs {
            ((3 * lhs.x.pow(2) + a) *
                modular_inverse(&(2 * &lhs.y), q).to_bigint().unwrap()) % q
        } else {
            ((&rhs.y - &lhs.y) *
                modular_inverse(&(&rhs.x - &lhs.x), q).to_bigint().unwrap()) % q
        };
        if lambda.is_negative() {
            lambda += q;
        }
        let mut x = (lambda.pow(2) - &lhs.x - &rhs.x) % q;
        if x.is_negative() {
            x += q;
        }
        let mut y = (&lambda * (&lhs.x - &x) - &lhs.y) % q;
        if y.is_negative() {
            y += q;
        }
        Self {
            x,
            y
        }
    }

    pub fn point_multiplication(lhs: usize, rhs: &Point, q: &BigUint, a: &BigInt) -> Self {
        let mut result = rhs.clone();
        for _ in 0..(lhs - 1) {
            result = Self::point_addition(&result, rhs, q, a);
        }
        result
    }
}
