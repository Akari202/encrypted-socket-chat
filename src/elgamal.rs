use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use crate::math::{modular_inverse, modular_pow};
use crate::math::prime::new_prime;
use crate::math::point::Point;
use std::ops::Sub;
use std::path::PathBuf;
use log::{error, info, trace, debug};
use num::bigint::{RandBigInt, ToBigInt};
use num::{BigUint, BigInt, ToPrimitive};
use rand::prelude::ThreadRng;
use rand::Rng;
use num::Signed;

const UPPER_BOUND: usize = 32;
const Y_BIT_SIZE: u64 = 64;

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct PublicKey {
    generator: Point,
    a: BigInt,
    b: BigInt,
    public_point: Point,
    modulus: BigUint
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct PrivateKey {
    multiplier: usize,
    modulus: BigUint,
    a: BigInt
}

#[derive(Debug)]
pub struct KeySet {
    private_key: PrivateKey,
    public_key: PublicKey,
    bit_length: u64
}

impl PrivateKey {
    pub fn new(multiplier: usize, modulus: BigUint, a: BigInt) -> Self {
        Self {
            multiplier,
            modulus,
            a
        }
    }

    pub fn decrypt(&self, input: &Point, halfmask: &Point) -> Result<Point, Box<dyn Error>> {
        trace!("Running decrypt with point: {} and halfmask: {}", input, halfmask);
        let fullmask = Point::point_multiplication(
            self.multiplier,
            halfmask,
            &self.modulus,
            &self.a
        )
            .negative();
        let decrypted = Point::point_addition(
            input,
            &fullmask,
            &self.modulus,
            &self.a
        );
        trace!("Decrypted: {}", &decrypted);
        Ok(decrypted)
    }

    pub fn decrypt_sequence_to_string(&self, input: &[(Point, Point)]) -> Result<String, Box<dyn Error>> {
        input.iter().map(|i| {
            // TODO: add proper error handling
            Ok(self.decrypt(&i.0, &i.1)?.x().to_u8().unwrap() as char)
        }).collect()
    }

    pub fn save_to_file(&self, mut file: File) -> Result<(), Box<dyn Error>> {
        let data = format!(
            "{}\n{}\n{}",
            self.multiplier,
            self.modulus,
            self.a
        );
        Ok(file.write_all(data.as_bytes())?)
    }

    pub fn load_key(name: &str) -> Result<Self, Box<dyn Error>> {
        let name = format!("{}.elg", name);
        info!("Loading Key: {}", name);
        let key_root = KeySet::get_key_root()?;
        let file_name = key_root.join(name);
        debug!("Key File: {:?}", file_name);
        let lines: Vec<String> = fs::read_to_string(file_name)?
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(lines.len(), 3);
        let multiplier = lines[0].parse::<usize>()?;
        let modulus = lines[1].parse::<BigUint>()?;
        let a = lines[2].parse::<BigInt>()?;
        Ok(Self {
            multiplier,
            modulus,
            a
        })
    }
}

impl PublicKey {
    pub fn new(generator: Point, public_point: Point, modulus: BigUint, a: BigInt, b: BigInt) -> Self {
        Self {
            generator,
            public_point,
            modulus,
            a,
            b
        }
    }

    pub fn save_to_file(&self, mut file: File) -> Result<(), Box<dyn Error>> {
        let data = format!(
            "{}\n{}\n{}\n{}\n{}",
            self.generator,
            self.public_point,
            self.modulus,
            self.a,
            self.b
        );
        Ok(file.write_all(data.as_bytes())?)
    }

    pub fn encrypt(&self, rng: &mut ThreadRng, input: &Point) -> (Point, Point) {
        trace!("Running enrypt: {}", input);
        let m = rng.gen_range(2..UPPER_BOUND);
        let halfmask = Point::point_multiplication(m, &self.generator, &self.modulus, &self.a);
        let fullmask = Point::point_multiplication(m, &self.public_point, &self.modulus, &self.a);
        let ciphertext = Point::point_addition(input, &fullmask, &self.modulus, &self.a);
        (ciphertext, halfmask)
    }

    pub fn encrypt_string(&self, rng: &mut ThreadRng, input: &str) -> Vec<(Point, Point)> {
        input.chars().map(|i| {
            let point = Point::new(
                BigInt::from(i as u8),
                rng.gen_bigint(Y_BIT_SIZE)
            );
            self.encrypt(rng, &point)
        }).collect()
    }

    pub fn load_key(name: &str) -> Result<Self, Box<dyn Error>> {
        let name = format!("{}.elg.pub", name);
        info!("Loading Key: {}", name);
        let key_root = KeySet::get_key_root()?;
        let file_name = key_root.join(name);
        debug!("Key File: {:?}", file_name);
        let lines: Vec<String> = fs::read_to_string(file_name)?
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(lines.len(), 5);
        let generator = lines[0].parse::<Point>()?;
        let public_point = lines[1].parse::<Point>()?;
        let modulus = lines[2].parse::<BigUint>()?;
        let a = lines[3].parse::<BigInt>()?;
        let b = lines[4].parse::<BigInt>()?;
        Ok(Self {
            generator,
            public_point,
            modulus,
            a,
            b
        })
    }
}


impl KeySet {
    pub fn new(bit_length: u64) -> Self {
        info!("Generating new ElGamal keyset");
        let q = new_prime(bit_length);
        // WARN: no idea if this is a good idea but everything is the same bit length
        let mut rng = rand::thread_rng();
        let mut a;
        let mut b;
        loop {
            a = rng.gen_bigint(bit_length);
            b = rng.gen_bigint(bit_length);
            let discriminant = (
                modular_pow(
                    &a.abs().to_biguint().unwrap(),
                    &BigUint::from(3u8),
                    &q
                ) * 4u8 +
                modular_pow(
                    &b.abs().to_biguint().unwrap(),
                    &BigUint::from(2u8),
                    &q
                ) * 27u8
            ) % &q;
            if discriminant != BigUint::ZERO {
                break
            }
        }
        let multiplier = rng.gen_range(2..UPPER_BOUND);
        // let generator_x = rng.gen_bigint(bit_length);
        // let generator_y = rng.gen_bigint(bit_length);
        let generator_x = BigInt::ZERO;
        let generator_y = b.clone();
        let generator = Point::new(generator_x, generator_y);
        let public_point = Point::point_multiplication(
            multiplier,
            &generator,
            &q,
            &a
        );


        Self {
            private_key: PrivateKey::new(multiplier, q.clone(), a.clone()),
            public_key: PublicKey::new(generator, public_point, q.clone(), a.clone(), b),
            bit_length
        }
    }

    pub fn save_keys(&self, name: &str) -> Result<(), Box<dyn Error>> {
        info!("Saving ElGamal keyset {}", name);
        let key_root = Self::get_key_root()?;
        let public_file = File::create(key_root.join(format!("{}.elg.pub", name)))?;
        self.public_key.save_to_file(public_file)?;
        let private_file = File::create(key_root.join(format!("{}.elg", name)))?;
        self.private_key.save_to_file(private_file)?;
        Ok(())
    }

    pub fn get_key_root() -> Result<PathBuf, Box<dyn Error>> {
        let home = dirs::home_dir().unwrap();
        let key_root = home.join(".amh_esc");
        if !key_root.exists() {
            fs::create_dir(&key_root)?;
        }
        Ok(key_root)
    }

    pub fn keypair_exists(name: &str) -> Result<bool, Box<dyn Error>> {
        let key_root = KeySet::get_key_root()?;
        let name = format!("{}.elg", name);
        let private_file_name = key_root.join(name.clone());
        let name = format!("{}.pub", name);
        let public_file_name = key_root.join(name);
        // WARN: error prone
        Ok(private_file_name.try_exists()? && public_file_name.try_exists()?)
    }
}
