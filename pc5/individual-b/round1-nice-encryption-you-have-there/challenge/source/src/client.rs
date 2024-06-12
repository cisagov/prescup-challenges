
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use openssl::symm::Mode;
use std::{env, error::Error, io::Read, net::TcpStream, thread::sleep, time::Duration};

mod common;

fn connect_read_loop_body(server: &str, in_buf: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(format!("{}:{}", server, common::PORT))?;
    stream.read_to_end(in_buf)?;
    common::aes(in_buf, Mode::Decrypt)?;

    Ok(())
}

fn main() {
    let server = match env::args().find(|e| e == "--test") {
        Some(_) => "localhost",
        None => "challenge.us",
    };

    let mut in_buf = vec![];

    loop {
        if let Err(e) = connect_read_loop_body(server, &mut in_buf) {
            println!("{}", e);
            sleep(Duration::from_secs(2));
        }

        in_buf.clear();
    }
}

