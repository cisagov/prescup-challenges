// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use std::fs;
use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time;
use std::thread;

fn retrieve_flag() -> String {
    match fs::read_to_string("flag.txt") {
        Ok(f) => f,
        Err(e) => format!(
            "Encountered an error when attempting to retrieve your flag. \
        Please report the following error to support: {}",
            e.to_string()
        ),
    }
}

fn handle_client(mut stream: TcpStream) {
    let flag = retrieve_flag();
    if let Err(e) = stream.write_all(flag.as_bytes()) {
        println!("Got a write_all error: {}", e.to_string());
    };
    thread::sleep(time::Duration::from_secs(10));
    if let Err(e) = stream.shutdown(Shutdown::Both) {
        println!("Got a shutdown error: {}", e.to_string());
    };
}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:2345").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_client(stream),
            Err(e) => println!("Got an error from an incoming connection: {}", e.to_string()),
        }
    }
}
