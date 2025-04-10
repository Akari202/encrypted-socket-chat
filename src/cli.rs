use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Instant;
use log::{info, trace};
use crate::rsa::{Key, KeySet};
use num::BigUint;
use rayon::prelude::*;

#[derive(Parser)]
#[command(name = "rsa")]
#[command(version, about = "A simple RSA encryption CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    #[command(flatten)]
    pub(crate) verbose: clap_verbosity_flag::Verbosity
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate RSA key pair
    Keygen {
        /// The name to save the public and private keys under
        #[arg(short, long)]
        key_name: String,
        /// The number of bits of salting to use, defaults to 6
        #[arg(short, long, default_value_t = 6)]
        salt_bits: u32,
        /// The key bit length to use, defaults to 4096
        #[arg(short, long, default_value_t = 4096)]
        bit_length: u64
    },
    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        /// Output file for the encrypted data (if not provided, print to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Public key name to use for encryption
        #[arg(short, long)]
        key_name: String,
    },
    /// Decrypt a file
    Decrypt {
        /// Input file to decrypt
        #[arg(short, long)]
        input: PathBuf,
        /// Output file for the decrypted data (if not provided, print to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Private key name to use for decryption
        #[arg(short, long)]
        key_name: String,
    },
}

impl Commands {
    pub fn execute(&self) -> Result<(), Box<dyn Error>> {
        match self {
            Commands::Keygen {key_name, salt_bits, bit_length} => {
                let perf_start = Instant::now();
                println!("Generating Keypair, this may take a moment...");
                let keyset = KeySet::new(*salt_bits, *bit_length);
                println!("Saving keys with name {}", key_name);
                keyset.save_keys(key_name)?;
                info!("Key generation took {:?}", perf_start.elapsed());
                Ok(())
            }
            Commands::Encrypt { input, output, key_name } => {
                let perf_start = Instant::now();
                println!("Encrypting input file...");
                let mut rng = rand::thread_rng();
                let public_key = Key::load_public_key(key_name)?;
                let plaintext = fs::read_to_string(input)?;
                trace!("Encrypting input text: {}", &plaintext);
                let ciphertext: Vec<BigUint> = plaintext
                    .chars()
                    .map(|i| {
                        public_key.encrypt(&mut rng, i as u8)
                    })
                    .collect();
                match output {
                    None => {
                        for i in ciphertext {
                            println!("{}", i);
                        }
                    }
                    Some(output) => {
                        let data = ciphertext
                            .iter()
                            .map(|i| {i.to_string()})
                            .collect::<Vec<String>>()
                            .join("\n");
                        let mut file = File::create(output)?;
                        file.write_all(data.as_bytes())?;
                    }
                }
                info!("Encryption took {:?}", perf_start.elapsed());
                Ok(())
            }
            Commands::Decrypt { input, output, key_name } => {
                let perf_start = Instant::now();
                println!("Decrypting input file, this may take a while...");
                let private_key = Key::load_private_key(key_name)?;
                let ciphertext: Vec<BigUint> = fs::read_to_string(input)?
                    .lines()
                    .map(|i| {
                        i.parse::<BigUint>().unwrap()
                    })
                    .collect();
                trace!("Decrypting input text: {:?}", &ciphertext);
                let plaintext: String = ciphertext
                    .par_iter()
                    .map(|i| {
                        private_key.decrypt(i).unwrap() as char
                    })
                    .collect::<String>();
                match output {
                    None => {
                        println!("{}", plaintext);
                    }
                    Some(output) => {
                        let mut file = File::create(output)?;
                        file.write_all(plaintext.as_bytes())?;
                    }
                }
                info!("Decryption took {:?}", perf_start.elapsed());
                Ok(())
            }
        }
    }
}
