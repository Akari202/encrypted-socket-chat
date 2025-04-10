use std::fs;
use num::{BigInt, BigUint};
use crate::rsa::KeySet;
use serial_test::serial;
use crate::rsa::Key;
use test_log::test;
use crate::math::{modular_inverse, modular_pow};
use crate::math::point::Point;

const INPUT: &str = "./src/rsa.rs";
const KEY_NAME: &str = "test_keys";
const SALT_BITS: u32 = 4;
const BIT_LENGTH: u64 = 128;

#[test]
#[serial]
fn test_rsa() {
    let mut rng = rand::thread_rng();
    let input_plaintext = fs::read_to_string(INPUT).unwrap();

    // Key generation
    if !KeySet::keypair_exists(KEY_NAME).unwrap() {
        let keyset = KeySet::new(SALT_BITS, BIT_LENGTH);
        keyset.save_keys(KEY_NAME).unwrap();
    }

    // Encryption
    let public_key = Key::load_public_key(KEY_NAME).unwrap();
    let ciphertext: Vec<BigUint> = input_plaintext
        .chars()
        .map(|i| {
            public_key.encrypt(&mut rng, i as u8)
        })
        .collect();

    // Decryption
    let private_key = Key::load_private_key(KEY_NAME).unwrap();
    let plaintext: String = ciphertext
        .iter()
        .map(|i| {
            private_key.decrypt(i).unwrap() as char
        })
        .collect::<String>();

    // Assertions
    assert_eq!(plaintext, input_plaintext)
}

#[test]
#[serial]
fn test_key_loading() {
    let keyset = KeySet::new(SALT_BITS, BIT_LENGTH);
    keyset.save_keys(KEY_NAME).unwrap();
    let public_key = Key::load_public_key(KEY_NAME).unwrap();
    let private_key = Key::load_private_key(KEY_NAME).unwrap();

    assert_eq!(public_key, keyset.get_public_key());
    assert_eq!(private_key, keyset.get_private_key());
}

#[test]
fn test_modular_inverse() {
    let q = BigInt::from(43u8);
    assert_eq!(modular_inverse(&BigInt::from(16u8), &q), BigUint::from(35u8));
    assert_eq!(modular_inverse(&BigInt::from(21u8), &q), BigUint::from(41u8));
    assert_eq!(modular_inverse(&BigInt::from(37u8), &q), BigUint::from(7u8));
    assert_eq!(modular_inverse(&BigInt::from(-8i8), &q), BigUint::from(16u8));
    assert_eq!(modular_inverse(&BigInt::from(-343i16), &BigInt::from(5u8)), BigUint::from(3u8));
}

#[test]
fn test_modular_pow() {
    let q = BigUint::from(840u16);
    assert_eq!(modular_pow(
            &BigUint::from(43u8),
            &BigUint::from(67u8),
            &q
            ),
        BigUint::from(547u16)
        );
    assert_eq!(modular_pow(
            &BigUint::from(4u8),
            &BigUint::from(80u8),
            &q
            ),
        BigUint::from(16u8)
        );
    assert_eq!(modular_pow(
            &BigUint::from(4u8),
            &BigUint::from(81u8),
            &q
            ),
        BigUint::from(64u8)
        );
}

#[test]
fn test_point_addition() {
    let test_point = Point::new_usize(32, 32);
    assert_eq!(Point::point_addition(
            &test_point,
            &test_point,
            &BigUint::from(43u8),
            &BigInt::from(4u8)
    ), Point::new_usize(31, 8));
    assert_eq!(Point::point_addition(
            &Point::new_usize(11, 17),
            &Point::new_usize(83, 23),
            &BigUint::from(97u8),
            &BigInt::from(2u8)
    ), Point::new_usize(67, 43));
}

#[test]
fn test_point_multiplication() {
    assert_eq!(Point::point_multiplication(
            5,
            &Point::new_usize(32, 32),
            &BigUint::from(43u8),
            &BigInt::from(4u8)
    ), Point::new_usize(26, 16));
}
