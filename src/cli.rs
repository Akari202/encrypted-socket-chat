use std::error::Error;
use std::{fs, thread};
use std::fmt::Formatter;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::time::Instant;
use aes::Aes128;
use aes::cipher::KeyInit;
use log::{info, trace};
use num::BigUint;
use rayon::prelude::*;
use crate::{elgamal, rsa};
use crate::math::point::{ParsePointError, Point};
use std::string::String;
use clap::builder::TypedValueParser;
use num::bigint::ParseBigIntError;
use rayon::iter::split;

const EXCHANGE_HEADER: &str = "[[ESC AES Exchange:]]";
const EXCHANGE_LENGTH: u8 = 2;

#[derive(Parser)]
#[command(name = "esc")]
#[command(version, about = "A simple encrypted socket chat program", long_about = None)]
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
        /// The encryption type to use, defaults to RSA
        /// other default values assume RSA, using these values
        /// with other encryption schemes could be extremely slow
        #[arg(short, long, default_value_t = Scheme::Rsa)]
        encryption_scheme: Scheme,
        /// The name to save the public and private keys under
        #[arg(short, long)]
        key_name: String,
        /// The number of bits of salting to use, defaults to 6
        /// salting is not currently implemented for elgamal
        #[arg(short, long, default_value_t = 6)]
        salt_bits: u32,
        /// The key bit length to use, defaults to 4096
        #[arg(short, long, default_value_t = 4096)]
        bit_length: u64
    },
    /// Open socket chatting
    Chat {
        /// Socket name and path, defaults to '/tmp/esc.sock'
        #[arg(short, long)]
        socket: Option<PathBuf>,
        /// The encryption type to use, defaults to RSA
        /// other default values assume RSA, using these values
        /// with other encryption schemes could be extremely slow
        #[arg(short, long, default_value_t = Scheme::Rsa)]
        encryption_scheme: Scheme,
        #[command(subcommand)]
        chat_direction: ChatDirection
    }
}

#[derive(Subcommand)]
pub enum ChatDirection {
    Join {
        /// Private key name to use for decryption
        #[arg(short, long, required = true)]
        private_key_name: String
    },
    Host {
        /// The secret passphrase to use for AES encryption
        #[arg(short, long, required = true)]
        secret_phrase: String,
        /// Public key name to use for encryption
        #[arg(short, long, required = true)]
        public_key_name: String,
    }
}

#[derive(ValueEnum, Debug, PartialEq, Copy, Clone)]
pub enum Scheme {
    Rsa,
    Elgamal
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Scheme::Rsa => {
                write!(f, "rsa");
            }
            Scheme::Elgamal => {
                write!(f, "ElGamal");
            }
        }
        Ok(())
    }
}

impl Commands {
    pub fn execute(&self) -> Result<(), Box<dyn Error>> {
        match self {
            Commands::Keygen {
                encryption_scheme,
                key_name,
                salt_bits,
                bit_length
            } => {
                let perf_start = Instant::now();
                println!("Generating Keypair, this may take a moment...");
                match encryption_scheme {
                    Scheme::Rsa => {
                        let keyset = rsa::KeySet::new(*salt_bits, *bit_length);
                        println!("Saving keys with name {}", key_name);
                        keyset.save_keys(key_name)?;
                    }
                    Scheme::Elgamal => {
                        let keyset = elgamal::KeySet::new(*bit_length);
                        println!("Saving keys with name {}", key_name);
                        keyset.save_keys(key_name)?;
                    }
                }
                info!("Key generation took {:?}", perf_start.elapsed());
                Ok(())
            }
            // WARN: This is going to be a monolithic tangle lol
            Commands::Chat {
                socket,
                encryption_scheme,
                chat_direction
            } => {
                let socket_path = if socket.is_none() {
                    PathBuf::from("/tmp/esc.sock")
                } else {
                    socket.clone().unwrap().to_path_buf()
                };
                if fs::metadata(&socket_path).is_ok() {
                    info!("A socket is already present. Deleting...");
                    fs::remove_file(&socket_path)?;
                }
                let listener = UnixListener::bind(&socket_path)?;
                let aes_cipher: Aes128;
                match chat_direction {
                    ChatDirection::Join {
                        private_key_name
                    } => {
                        let aes_exchange = watch_for_header(listener)?;
                        let aes_decrypted = match encryption_scheme {
                            Scheme::Rsa => {
                                let key = rsa::Key::load_private_key(private_key_name)?;
                                key.decrypt_sequence(
                                    &aes_exchange
                                        .split(",")
                                        .map(|i| {
                                            i.parse::<BigUint>()
                                        })
                                        .collect::<Result<Vec<_>, _>>()?
                                )?
                                    .iter()
                                    .map(|i| {
                                        *i as char
                                    })
                                    .collect::<String>()
                            }
                            Scheme::Elgamal => {
                                let key = elgamal::PrivateKey::load_key(private_key_name)?;
                                let all_points = aes_exchange
                                    .split("|")
                                    .map(|i| {
                                        i.parse::<Point>()
                                    })
                                    .collect::<Result<Vec<_>, _>>()?;
                                let mut all_points = all_points.iter();
                                let point_pairs = (0usize..=(all_points.len() / 2))
                                    .map(|_| {
                                        (all_points.next().unwrap().clone(), all_points.next().unwrap().clone())
                                    })
                                    .collect::<Vec<_>>();
                                key.decrypt_sequence_to_string(&point_pairs)?
                            }
                        };
                        let secret_phrase = aes_decrypted
                            .chars()
                            .map(|i| {
                                i as u8
                            })
                            .collect::<Vec<u8>>();
                        dbg!(aes_exchange);
                        dbg!(aes_decrypted);
                        aes_cipher = Aes128::new_from_slice(&secret_phrase).unwrap();
                    }
                    ChatDirection::Host {
                        secret_phrase,
                        public_key_name
                    } => {
                        let secret_phrase = secret_phrase
                            .chars()
                            .map(|i| {
                                i as u8
                            })
                            .collect::<Vec<u8>>();
                        aes_cipher = Aes128::new_from_slice(&secret_phrase).unwrap();

                    }
                }
                dbg!(aes_cipher);
                Ok(())
            }
        }
    }
}


fn watch_for_header(listener: UnixListener) -> Result<String, Box<dyn Error>> {
    let mut exchange: String = String::new();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let stream = BufReader::new(stream);
                let mut header = false;
                for line in stream.lines() {
                    let line = line.unwrap();
                    println!("Reading: {}", line.clone());
                    if line.clone() == EXCHANGE_HEADER {
                        header = true;
                    }
                    if header {
                        exchange = line;
                        break;
                    }
                }
            }
            Err(err) => {
                println!("Error: {}", err);
            }
        }
    }
    Err("Unable to read header".into())
}