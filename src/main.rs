#![feature(iter_array_chunks)]
#![feature(unix_socket_peek)]
#![feature(array_chunks)]
// #![feature(future_join)]

#![allow(dead_code)]
extern crate core;

mod rsa;
mod elgamal;
mod math;
mod cli;
#[cfg(test)]
mod tests;

use std::error::Error;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixListener;
use std::thread;
use clap::builder::TypedValueParser;
use clap::Parser;
use num::BigInt;
use crate::cli::Cli;
use crate::math::xgcd;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    env_logger::Builder::new()
        .filter_level(cli.verbose.into())
        .init();
    cli.command.execute()

    // Ok(())
}
