#![feature(future_join)]
#![allow(dead_code)]
extern crate core;

mod rsa;
mod elgamal;
mod math;
mod cli;
#[cfg(test)]
mod tests;

use std::error::Error;
use clap::builder::TypedValueParser;
use clap::Parser;
use num::BigInt;
use crate::cli::Cli;
use crate::math::xgcd;

fn main() -> Result<(), Box<dyn Error>> {
    // let cli = Cli::parse();
    // env_logger::Builder::new()
    //     .filter_level(cli.verbose.into())
    //     .init();
    //cli.command.execute()
    Ok(())
}
