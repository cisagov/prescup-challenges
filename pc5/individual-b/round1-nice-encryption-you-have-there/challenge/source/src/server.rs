
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

mod common;

use lazy_static::lazy_static;
use openssl::symm::Mode;
use rand::Rng;

use std::{
    error::Error,
    io::Write,
    net::{TcpListener, TcpStream},
    process::Command,
};

const ALICE_FULL_TEXT: &str = include_str!("../alice_in_wonderland.txt");
const ERROR_TOKEN: &str = "token{TOKEN COULD NOT BE RETRIEVED, PLEASE REPORT}";
const FREQUENCY: u64 = 10000;

lazy_static! {
    static ref ALICE_CHAPTERS: Vec<&'static str> = ALICE_FULL_TEXT.split("----------").collect();
}

static mut TOKEN: Option<String> = None;

fn run_vmtoolsd_cmd() -> Result<String, ()> {
    let result = Command::new("vmtoolsd")
        .args(["--cmd", "info-get guestinfo.token"])
        .output();

    let result_out = match result {
        Ok(v) => v,
        Err(e) => {
            println!("ERROR: vmtoolsd command failed with error: {}", e);
            return Err(());
        }
    };

    let result_str = match String::from_utf8(result_out.stdout) {
        Ok(v) => v,
        Err(e) => {
            println!(
                "ERROR: Result from vmtoolsd command could not be parsed as a UTF-8 string: {}",
                e
            );
            return Err(());
        }
    };

    if result_str.trim().is_empty() {
        println!("ERROR: Result from vmtoolsd command was empty.");
        return Err(());
    }

    Ok(format!("token{{{}}}", result_str.trim()))
}

fn try_get_token() -> String {
    unsafe {
        if TOKEN.is_none() {
            match run_vmtoolsd_cmd() {
                Ok(v) => TOKEN = Some(v),
                Err(_) => return ERROR_TOKEN.to_string(),
            }
        }

        TOKEN.clone().unwrap()
    }
}

fn get_random_alice_chapter() -> &'static str {
    let mut rng = rand::thread_rng();

    let chapter = rng.gen_range(0..ALICE_CHAPTERS.len());

    ALICE_CHAPTERS[chapter]
}

fn accept_connection(s: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut message = String::new();

    message.push_str(get_random_alice_chapter());
    let mut rng = rand::thread_rng();
    if rng.gen_range(0..FREQUENCY) == 0 {
        let token = try_get_token();
        message.push_str(&token);
        println!("INFO: Embedded token in outgoing message: {}", token);
    }
    message.push_str(get_random_alice_chapter());

    let enc_message = common::aes(message.as_bytes(), Mode::Encrypt)?;

    s.write_all(&enc_message)?;

    Ok(())
}

fn main() {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", common::PORT)).unwrap();

    let mut accept_count = 0u64;

    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                if let Err(e) = accept_connection(&mut s) {
                    println!("ERROR: Error in accept handler: {}", e);
                }
                accept_count += 1;
            }
            Err(e) => println!("ERROR: Error on accept: {}", e),
        }
        if accept_count % FREQUENCY == 0 {
            println!(
                "INFO: Server has accepted {} connections so far.",
                accept_count
            );
        }
    }
}

