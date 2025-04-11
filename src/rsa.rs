use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use crate::math::{modular_inverse, modular_pow};
use crate::math::prime::new_prime;
use std::ops::Sub;
use std::path::PathBuf;
use log::{error, info, trace, debug};
use num::bigint::{RandBigInt, ToBigInt};
use num::{BigUint, ToPrimitive};
use rand::prelude::ThreadRng;

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct Key {
    exponent: BigUint,
    modulus: BigUint,
    salt_bits: u32
}

#[derive(Debug)]
pub struct KeySet {
    private_key: Key,
    public_key: Key,
    phi: BigUint,
    primes: (BigUint, BigUint),
    bit_length: u64
}

impl Key {
    pub fn new(exponent: BigUint, modulus: BigUint, salt_bits: u32) -> Self {
        Self {
            exponent,
            modulus,
            salt_bits
        }
    }

    pub fn encrypt(&self, rng: &mut ThreadRng, input: u8) -> BigUint {
        trace!("Running enrypt: {}", input);
        let salt = rng.gen_biguint(self.salt_bits as u64);
        trace!("Salt: {:b}", &salt);
        let input = BigUint::from(input);
        trace!("Input: {:b}", &input);
        let input = (input << self.salt_bits) | salt;
        trace!("Salted value: {:b}", &input);
        modular_pow(&input, &self.exponent, &self.modulus)
    }

    pub fn encrypt_sequence(&self, rng: &mut ThreadRng, input: &[u8]) -> Vec<BigUint> {
        input.iter().map(|i| {
            self.encrypt(rng, *i)
        }).collect()
    }

    pub fn encrypt_string(&self, rng: &mut ThreadRng, input: &str) -> Vec<BigUint> {
        input.chars().map(|i| {
            self.encrypt(rng, i as u8)
        }).collect()
    }

    pub fn decrypt(&self, input: &BigUint) -> Result<u8, Box<dyn Error>> {
        trace!("Running decrypt: {}", input);
        let decrypted = modular_pow(input, &self.exponent, &self.modulus);
        trace!("Salted decrypted: {}", &decrypted);
        let desalted = (&decrypted >> self.salt_bits).to_u8();
        match desalted {
            None => {
                error!("Could not decrypt.\nInput: {}\nDecrypted: {}", &input, &decrypted);
                Err("Decryption failed".into())
            }
            Some(desalted) => {
                trace!("Unsalted decrypted: {}", &desalted);
                Ok(desalted)
            }
        }
    }

    pub fn decrypt_sequence(&self, input: &[BigUint]) -> Result<Vec<u8>, Box<dyn Error>> {
        input.iter().map(|i| {
            self.decrypt(i)
        }).collect()
    }

    pub fn decrypt_sequence_to_string(&self, input: &[BigUint]) -> Result<String, Box<dyn Error>> {
        input.iter().map(|i| {
            Ok(self.decrypt(i)? as char)
        }).collect()
    }


    pub fn save_to_file(&self, mut file: File) -> Result<(), Box<dyn Error>> {
        let data = format!("{}\n{}\n{}", self.exponent, self.modulus, self.salt_bits);
        Ok(file.write_all(data.as_bytes())?)
    }

    pub fn load_public_key(name: &str) -> Result<Self, Box<dyn Error>> {
        let name = format!("{}.rsa.pub", name);
        Self::load_key(&name)
    }

    pub fn load_private_key(name: &str) -> Result<Self, Box<dyn Error>> {
        let name = format!("{}.rsa", name);
       Self::load_key(&name)
    }

    fn load_key(name: &str) -> Result<Self, Box<dyn Error>> {
        info!("Loading Key: {}", name);
        let key_root = KeySet::get_key_root()?;
        let file_name = key_root.join(name);
        debug!("Key File: {:?}", file_name);
        let lines: Vec<String> = fs::read_to_string(file_name)?
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(lines.len(), 3);
        let exponent = lines[0].parse::<BigUint>()?;
        let modulus = lines[1].parse::<BigUint>()?;
        let salt_bits = lines[2].parse::<u32>()?;
        Ok(Self {
            exponent,
            modulus,
            salt_bits
        })
    }

    #[cfg(test)]
    pub fn get_exponent(&self) -> BigUint {
        self.exponent.clone()
    }

    #[cfg(test)]
    pub fn get_modulus(&self) -> BigUint {
        self.modulus.clone()
    }
}

impl KeySet {
    pub fn new(salt_bits: u32, bit_length: u64) -> Self {
        info!("Generating new RSA keyset");
        let prime_bit_length = bit_length / 2;
        let p = new_prime(prime_bit_length);
        let q = new_prime(prime_bit_length);
        let n = &p * &q;
        let phi = p.clone().sub(1u8) * q.clone().sub(1u8);
        let e = BigUint::from(2usize.pow(16) + 1);
        let d = modular_inverse(
            &e.to_bigint().unwrap(),
            &phi.to_bigint().unwrap()
            );
        Self {
            private_key: Key::new(d, n.clone(), salt_bits),
            public_key: Key::new(e, n.clone(), salt_bits),
            phi,
            primes: (p, q),
            bit_length
        }
    }

    pub fn save_keys(&self, name: &str) -> Result<(), Box<dyn Error>> {
        info!("Saving RSA keyset {}", name);
        let key_root = Self::get_key_root()?;
        let public_file = File::create(key_root.join(format!("{}.rsa.pub", name)))?;
        self.public_key.save_to_file(public_file)?;
        let private_file = File::create(key_root.join(format!("{}.rsa", name)))?;
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

    #[cfg(test)]
    pub fn get_public_key(&self) -> Key {
        self.public_key.clone()
    }

    #[cfg(test)]
    pub fn get_private_key(&self) -> Key {
        self.private_key.clone()
    }

    #[cfg(test)]
    pub fn get_phi(&self) -> BigUint {
        self.phi.clone()
    }

    #[cfg(test)]
    pub fn get_primes(&self) -> (BigUint, BigUint) {
        self.primes.clone()
    }

    pub fn keypair_exists(name: &str) -> Result<bool, Box<dyn Error>> {
        let key_root = KeySet::get_key_root()?;
        let name = format!("{}.rsa", name);
        let private_file_name = key_root.join(name.clone());
        let name = format!("{}.pub", name);
        let public_file_name = key_root.join(name);
        // WARN: error prone
        Ok(private_file_name.try_exists()? && public_file_name.try_exists()?)
    }
}
