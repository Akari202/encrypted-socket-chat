use log::{trace, debug};
use num::{BigUint, Integer, ToPrimitive};
use num::bigint::RandBigInt;
use rand::prelude::ThreadRng;
use crate::math::constants::{MILLER_RABIN_ROUNDS, SMALL_PRIMES};
use crate::math::modular_pow;

pub fn new_prime(bit_length: u64) -> BigUint {
    debug!("Generating {} bit prime", bit_length);
    let mut rng = rand::thread_rng();
    loop {
        let candidate: BigUint = rng.gen_biguint(bit_length);
        if is_prime(&candidate) {
            trace!("Successful Prime: {:?}", candidate);
            return candidate;
        }
        trace!("Failed Prime: {:?}", candidate);
    }
}

pub fn is_prime(candidate: &BigUint) -> bool {
    let mut rng = rand::thread_rng();
    candidate != &BigUint::ZERO ||
        candidate != &BigUint::from(2u8) ||
        !candidate.is_even() ||
        divide_small_primes(candidate) ||
        fermat(&mut rng, candidate) ||
        miller_rabin(&mut rng, candidate, MILLER_RABIN_ROUNDS)

}

fn divide_small_primes(number: &BigUint) -> bool {
    for i in SMALL_PRIMES.iter() {
        if number % &BigUint::from(*i) == BigUint::ZERO {
            return false
        }
    }
    true
}

fn fermat(rng: &mut ThreadRng, candidate: &BigUint) -> bool {
    let random = rng.gen_biguint_below(candidate);
    let exponent = candidate - BigUint::from(1u8);
    let result = modular_pow(&random, &exponent, candidate);
    result == BigUint::from(1u8)
}



// needs to be fixed
fn miller_rabin(rng: &mut ThreadRng, candidate: &BigUint, limit: usize) -> bool {
    let (d, s) = rewrite(candidate);
    let step = (s - &BigUint::from(1u8)).to_usize().unwrap();

    for _ in 0..limit {
        let a = rng.gen_biguint_range(&BigUint::from(2u8), &(candidate - &BigUint::from(1u8)));
        let mut x = modular_pow(&a, &d, candidate);
        if x == BigUint::from(1u8) || x == (candidate - &BigUint::from(1u8)) {
            continue
        }
        else {
            let mut break_early = false;
            for _ in 0..step {
                x = modular_pow(&x, &BigUint::from(2u8), candidate);
                if x == BigUint::from(1u8) {
                    return false
                }
                else if x == (candidate - &BigUint::from(1u8)) {
                    break_early = true;
                    break;
                }
            }
            if !break_early {
                return false
            }
        }
    }
    true
}

fn rewrite(n: &BigUint) -> (BigUint,BigUint) {
    let one: BigUint = BigUint::from(1u8);
    let mut s: BigUint = BigUint::ZERO;
    let mut d: BigUint = n - &one;

    while d.is_even() {
        d = d.div_floor(&BigUint::from(2u8));
        s += &one;
    }

    (d.clone(), s)
}
