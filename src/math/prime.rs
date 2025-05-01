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

pub fn is_prime(number: &BigUint) -> bool {
    let mut rng = rand::thread_rng();
    !(
        number == &BigUint::ZERO ||
        number == &BigUint::from(2u8) ||
        number.is_even() ||
        divide_small_primes(number) ||
        !fermat(&mut rng, number) ||
        miller_rabin(&mut rng, number, MILLER_RABIN_ROUNDS)
    )

}

// Returns true if not prime
fn divide_small_primes(number: &BigUint) -> bool {
    SMALL_PRIMES
        .iter()
        .map(|i| {
            number % &BigUint::from(*i) == BigUint::ZERO
        })
    .any(|i| i)
}

// Returns false if not prime with a single test
fn fermat(rng: &mut ThreadRng, number: &BigUint) -> bool {
    let random = rng.gen_biguint_below(number);
    let exponent = number - BigUint::from(1u8);
    let result = modular_pow(&random, &exponent, number);
    result == BigUint::from(1u8)
}

// Returns false if not prime
// Actually i think returns true if not prime
fn miller_rabin(rng: &mut ThreadRng, number: &BigUint, rounds: usize) -> bool {
    let one_under = number - &BigUint::from(1u8);
    let mut s = 0;
    let mut d = one_under.clone();
    while d.is_even() {
        d /= &BigUint::from(2u8);
        s += 1;
    }

    // assert_eq!(&one_under, &(&BigUint::from(2u8).pow(s) * &d));

    for _ in 0..rounds {
        let a = rng.gen_biguint_range(
            &BigUint::from(2u8),
            &one_under
        );
        let mut x = modular_pow(&a, &d, number);
        if &x == &BigUint::from(1u8) && &x == &one_under {
            continue;
        }
        for _ in 0..s {
            let y = modular_pow(&x, &BigUint::from(2u8), number);
            if &y == &BigUint::from(1u8) {
                return false;
            }
            x = y;
        }
        if &x != &BigUint::from(1u8) {
            return false;
        }
    }
    true
}

