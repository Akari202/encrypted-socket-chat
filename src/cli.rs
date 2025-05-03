use std::error::Error;
use std::{fs, io, thread};
use std::fmt::Formatter;
use std::fs::File;
use std::io::{stdin, BufRead, BufReader, Read, Stdin, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::time::Instant;
use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeySizeUser};
use aes::cipher::generic_array::GenericArray;
use log::{debug, info, trace};
use num::BigUint;
use rayon::prelude::*;
use crate::{elgamal, rsa};
use crate::math::point::{ParsePointError, Point};
use clap::builder::TypedValueParser;
use num::bigint::ParseBigIntError;
use std::string::String;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crossterm::cursor::MoveToColumn;
use crossterm::event::{Event, KeyCode};
use crossterm::execute;
use rand::{random, thread_rng, Rng};
use rayon::iter::split;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};

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
        /// Required becuase sometimes bad things are generated
        #[arg(short, long, required = true)]
        secret_phrase: Option<String>,
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
                match chat_direction {
                    ChatDirection::Join {
                        private_key_name
                    } => {
                        let mut stream = UnixStream::connect(socket_path)?;
                        let mut buf_reader = BufReader::new(stream.try_clone()?);
                        let mut header = false;
                        let mut encrypted = String::new();
                        for line in buf_reader.lines() {
                            let line = line.unwrap();
                            trace!("Reading: {}", line.clone());
                            if header {
                                encrypted = line;
                                break;
                            }
                            if line.clone() == EXCHANGE_HEADER {
                                header = true;
                            }
                        }
                        if encrypted.is_empty() {
                            return Err("Header not found".into())
                        }
                        debug!("Encrypted secret phrase: {}", encrypted);
                        let secret_phrase = match encryption_scheme {
                            Scheme::Rsa => {
                                let key = rsa::Key::load_private_key(private_key_name)?;
                                let encrypted = encrypted
                                    .split("|")
                                    .map(|i| {
                                        i.parse::<BigUint>()
                                    })
                                    .collect::<Result<Vec<BigUint>, _>>()?;
                                key.decrypt_sequence_to_string(&encrypted)?
                            }
                            Scheme::Elgamal => {
                                let key = elgamal::PrivateKey::load_key(private_key_name)?;
                                let encrypted = encrypted
                                    .split("|")
                                    .map(|i| {
                                        let points = i.split("%")
                                            .map(|j| {
                                                j.parse::<Point>()
                                            })
                                            .collect::<Result<Vec<Point>, _>>();
                                        match points {
                                            Ok(points) => {
                                                Ok((points[0].clone(), points[1].clone()))
                                            }
                                            Err(error) => {
                                                Err(error)
                                            }
                                        }
                                    })
                                    .collect::<Result<Vec<_>, _>>()?;
                                key.decrypt_sequence_to_string(&encrypted)?
                            }
                        };
                        info!("Decrypted secret phrase: {:?}", &secret_phrase);
                        let aes_cipher = build_aes_key(&secret_phrase)?;
                        info!("Ready to talk!");

                        message(Arc::new(aes_cipher), stream)?;
                    }
                    ChatDirection::Host {
                        secret_phrase,
                        public_key_name
                    } => {
                        let (aes_cipher, secret_phrase) = generate_aes_key(secret_phrase)?;
                        debug!("AES Cipher: {:?} and secret phrase {}", aes_cipher, secret_phrase);
                        if fs::metadata(&socket_path).is_ok() {
                            info!("A socket is already present. Deleting...");
                            fs::remove_file(&socket_path)?;
                        }
                        let listener = UnixListener::bind(&socket_path)?;
                        info!("Socket listener created");
                        let (mut stream, address) = listener.accept()?;
                        info!("Connection accepted: {:?}", address);
                        stream.write(EXCHANGE_HEADER.as_bytes())?;
                        stream.write("\n".as_bytes())?;
                        let mut rng = thread_rng();
                        let encrypted_phrase = match encryption_scheme {
                            Scheme::Rsa => {
                                let key = rsa::Key::load_public_key(public_key_name)?;
                                let encrypted = key.encrypt_string(&mut rng, &secret_phrase);
                                encrypted
                                    .iter()
                                    .map(|i| {
                                        format!("{}", i)
                                    })
                                    .collect::<Vec<String>>()
                                    .join("|")
                            }
                            Scheme::Elgamal => {
                                let key = elgamal::PublicKey::load_key(public_key_name)?;
                                let encrypted = key.encrypt_string(&mut rng, &secret_phrase);
                                encrypted
                                    .iter()
                                    .map(|i| {
                                        format!("{}%{}", i.0, i.1)
                                    })
                                    .collect::<Vec<String>>()
                                    .join("|")
                            }
                        };
                        info!("Writing encrypted secret phrase");
                        stream.write(encrypted_phrase.as_bytes())?;
                        stream.write("\n".as_bytes())?;
                        info!("Ready to talk!");

                        // let test_string = include_str!("cli.rs");
                        // let test_string = "Hello World!";
                        // trace!("Test string: {}", test_string);
                        // let test_string = encrypt_aes_string(test_string, &aes_cipher)?;
                        // trace!("Test string: {:?}", test_string);
                        // stream.write(&test_string)?;
                        // stream.write("\n".as_bytes())?;

                        message(Arc::new(aes_cipher), stream)?;
                    }
                }
                Ok(())
            }
        }
    }
}

fn generate_aes_key(secret_phrase: &Option<String>) -> Result<(Aes128, String), Box<dyn Error>> {
    let secret_phrase_word: String;
    let secret_phrase_bytes: [u8; 16];
    let aes_cipher: Aes128;
    match secret_phrase {
        None => {
            secret_phrase_bytes = random::<[u8; 16]>();
            secret_phrase_word = secret_phrase_bytes
                .iter()
                .map(|i| {
                    *i as char
                })
                .collect::<String>();
            aes_cipher = Aes128::new_from_slice(&secret_phrase_bytes).unwrap();
        }
        Some(secret_phrase) => {
            secret_phrase_word = secret_phrase.to_string();
            aes_cipher = build_aes_key(secret_phrase)?;
        }
    }
    Ok((aes_cipher, secret_phrase_word))
}

fn build_aes_key(secret_phrase: &str) -> Result<Aes128, Box<dyn Error>> {
    let secret_phrase_bytes: [u8; 16] = secret_phrase
        .chars()
        .map(|i| {
            i as u8
        })
        .collect::<Vec<u8>>()
        .try_into().unwrap();
    Ok(Aes128::new_from_slice(&secret_phrase_bytes).unwrap())
}

fn encrypt_aes_string(input: &str, cipher: &Aes128) -> Result<Vec<u8>, Box<dyn Error>> {
    let padded = format!("{:<width$}\n", input, width = (input.len() / 16 + 1) * 16 - 1);
    trace!("Padded: {}", padded);
    let mut blocks = padded
        .chars()
        .array_chunks::<16>()
        .map(|i| {
            let bytes = i
                .iter()
                .map(|j| {
                    *j as u8
                })
                .collect::<Vec<u8>>();
            GenericArray::from_slice(&bytes).to_owned()
        })
        .collect::<Vec<_>>();
    trace!("Blocks: {:?}", blocks);
    blocks.par_iter_mut()
        .for_each(|i| {
            cipher.encrypt_block(i);
        });
    trace!("Encrypted blocks: {:?}", blocks);
    Ok(blocks
        .iter()
        .flatten()
        .map(|i| {
            *i
        })
        .collect::<Vec<u8>>()
    )
}

fn encrypt_aes(input: &[u8], cipher: &Aes128) -> Result<Vec<u8>, Box<dyn Error>> {
    // let padded = format!("{:<width$}\n", input, width = (input.len() / 16 + 1) * 16 - 1);
    let pad_difference = (input.len() / 16 + 1) * 16;
    let mut padded = input.to_vec();
    for _ in 0..pad_difference {
        padded.push(0);
    }

    trace!("Padded: {:?}", padded);
    let mut blocks = padded
        .array_chunks::<16>()
        .map(|i| {
            GenericArray::from_slice(i).to_owned()
        })
        .collect::<Vec<_>>();
    trace!("Blocks: {:?}", blocks);
    blocks.par_iter_mut()
        .for_each(|i| {
            cipher.encrypt_block(i);
        });
    trace!("Encrypted blocks: {:?}", blocks);
    Ok(blocks
        .iter()
        .flatten()
        .map(|i| {
            *i
        })
        .collect::<Vec<u8>>()
    )
}

fn decrypt_aes_block(input: &[u8; 16], cipher: &Aes128) -> Result<String, Box<dyn Error>> {
    let mut block = GenericArray::from_slice(input).to_owned();
    cipher.decrypt_block(&mut block);
    debug!("Decrypted block: {:?}", block);
    Ok(block.iter()
        .map(|i| {
            *i as char
        })
        .collect::<String>()
    )
}

fn message(cipher: Arc<Aes128>, stream: UnixStream) -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    ctrlc::set_handler(move || {
        running_clone.store(false, Ordering::SeqCst);
    })?;

    let mut read_stream = BufReader::new(stream.try_clone()?);
    let mut write_stream = stream;

    let cipher_clone = Arc::clone(&cipher);
    let running_clone = Arc::clone(&running);

    let read_thread = thread::spawn(move || {
        let mut block_buffer = [0u8; 16];
        while running.load(Ordering::SeqCst) {
            if let Ok(_) = read_stream.read_exact(&mut block_buffer) {
                if block_buffer != [0u8; 16] {
                    debug!("Encrypted block read: {:?}", &block_buffer);
                    let decrypted = decrypt_aes_block(&block_buffer, &cipher_clone)
                        .expect("Decryption failed");
                    println!("\rThem: {}", decrypted.trim());
                }
            }
        }
    });

    let cipher_clone = Arc::clone(&cipher);

    let write_thread = thread::spawn(move || {
        let mut input_buffer = String::new();
        let mut stdout = io::stdout();

        while running_clone.load(Ordering::SeqCst) {
            if let Event::Key(event) = crossterm::event::read().expect("Failed to read terminal event") {
                match event.code {
                    KeyCode::Enter => {
                        if !input_buffer.is_empty() {
                            let encrypted_input = encrypt_aes_string(
                                &input_buffer,
                                &cipher_clone
                            )
                            .expect("Encryption failed");

                            debug!("Encrypted block to send: {:?}", &encrypted_input);

                            write_stream
                                .write_all(&encrypted_input)
                                .expect("Failed to write to stream");

                            println!("\rYou: {}", input_buffer);

                            input_buffer.clear();
                        }
                    }
                    KeyCode::Backspace => {
                        if !input_buffer.is_empty() {
                            input_buffer.pop();
                            execute!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine))
                                .expect("Failed to clear line");
                            print!("\r{}", input_buffer);
                            stdout.flush().expect("Failed to flush stdout");
                        }
                    }
                    KeyCode::Char(c) => {
                        input_buffer.push(c);
                        print!("{}", c);
                        stdout.flush().expect("Failed to flush stdout");
                    }
                    KeyCode::Esc => {
                        running_clone.store(false, Ordering::SeqCst);
                        break;
                    }
                    _ => {}
                }
            }
        }
    });

    read_thread.join().expect("Read thread panicked");
    write_thread.join().expect("Write thread panicked");

    disable_raw_mode()?;

    println!("\nProgram exited gracefully.");
    Ok(())
}


// fn message(cipher: Arc<Aes128>, stream: UnixStream) -> Result<(), Box<dyn Error>> {
//     enable_raw_mode()?;
//
//     let mut read_stream = BufReader::new(stream.try_clone()?);
//     let write_stream = stream;
//
//     let cipher_clone = Arc::clone(&cipher);
//     let read_thread = thread::spawn(move || {
//         let mut block_buffer = [0u8; 16];
//         loop {
//             if let Ok(_) = read_stream.read_exact(&mut block_buffer) {
//                 if block_buffer != [0u8; 16] {
//                     debug!("Encrypted block read: {:?}", &block_buffer);
//                     let decrypted = decrypt_aes_block(&block_buffer, &cipher_clone)
//                         .expect("Decryption failed");
//                     println!("{}", decrypted.trim());
//                 }
//             }
//         }
//     });
//
//     let cipher_clone = Arc::clone(&cipher);
//     let write_thread = thread::spawn(move || {
//         let mut stdin = io::stdin();
//         let mut write_stream = write_stream;
//         loop {
//             let mut input_buffer = String::new();
//             if stdin.read_line(&mut input_buffer).is_ok() {
//                 let encrypted_input =
//                     encrypt_aes_string(&format!("Them: {}", input_buffer), &cipher_clone)
//                         .expect("Encryption failed");
//                 debug!("Encrypted block to send: {:?}", &encrypted_input);
//                 write_stream
//                     .write_all(&encrypted_input)
//                     .expect("Failed to write to stream");
//                 print!("You: {}", input_buffer);
//             }
//         }
//     });
//
//     // Wait for both threads to finish
//     read_thread.join().expect("Read thread panicked");
//     write_thread.join().expect("Write thread panicked");
//
//     disable_raw_mode()?;
//
//     Ok(())
// }


