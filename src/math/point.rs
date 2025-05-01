use num::bigint::ToBigInt;
use num::{BigInt, Integer};
use num::Signed;
use num::BigUint;
use more_asserts as ma;
use std::str::FromStr;
use std::fmt;
use std::error::Error;

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
        if lhs == 0 {
            panic!("Unable to multiply by 0")
        }
        else if lhs == 1 {
            rhs.clone()
        }
        else if lhs == 2 {
            Self::point_addition(rhs, rhs, q, a)
        }
        else if lhs.is_even() {
            Self::point_multiplication(
                2,
                &Self::point_multiplication(lhs / 2, rhs, q, a),
                q,
                a
            )
            // let mut result = rhs.clone();
            // for _ in 0..(lhs / 2) {
            //     result = Self::point_addition(&result, &result, q, a);
            // }
            // result
        }
        else {
            Self::point_addition(
                rhs,
                &Self::point_multiplication(lhs - 1, rhs, q, a),
                q,
                a
            )
            // let mut result = rhs.clone();
            // for _ in 0..(lhs / 2) {
            //     result = Self::point_addition(&result, &result, q, a);
            // }
            // Self::point_addition(&result, rhs, q, a)
        }
    }

    pub fn negative(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: -self.y.clone()
        }
    }

    pub fn x(&self) -> &BigInt {
        &self.x
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Unable to parse point")]
pub struct ParsePointError;

impl FromStr for Point {
    type Err = ParsePointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (x, y) = s
            .strip_prefix("(")
            .and_then(|s| {
                s.strip_suffix(")")
            })
            .and_then(|s| {
                s.split_once(", ")
            }).ok_or(ParsePointError)?;

        let x = x.parse::<BigInt>().map_err(|_| ParsePointError)?;
        let y = y.parse::<BigInt>().map_err(|_| ParsePointError)?;

        Ok(Point {
            x,
            y
        })
    }
}
