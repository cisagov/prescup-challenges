/*
 * Copyright 2025 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
 *
 * This Software includes and/or makes use of Third-Party Software each subject to its own license.
 * DM25-0166 */

mod common;

use std::fmt::Display;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;
use std::{error::Error, net::TcpListener};

use base64::prelude::*;
use clap::Parser;
use strum::EnumString;

use common::{
    KeyBytes, KeyPair, Message, MessageDeserializeError, MessageDeserializeErrorType, PORT,
};
use x25519_dalek::SharedSecret;

#[derive(Parser, Debug)]
struct Args {
    /// base64-encoded private key (32 bytes)
    key: Option<String>,
    /// Path to write the most recently-negotiated shared secret. Default ./secret
    #[arg(default_value = "./secret")]
    secret_path: String,
    /// Path to create the capacity overflow file. Default ./capacity
    #[arg(default_value = "./capacity")]
    capacity_path: String,
}

fn handle_capacity_response<W: Write>(writer: &mut W) {
    // The file just needs to exist for this one.
    let capacity_response = match File::create(Args::parse().capacity_path) {
        Ok(_) => "Nice work! When you next run the grader at challenge.us, your capacity overflow will be recorded.",
        Err(e) => {
            eprintln!("Unable to create capacity overflow grading file because of error {e}");
            "You were able to cause the capacity overflow, but there was an error in grading. Please contact support."
        }
    };
    let message = Message::new(capacity_response.as_bytes());
    if let Err(e) = common::write_message(writer, &message) {
        eprintln!(
            "Caught error trying to send the capacity overflow acknowledgement to the competitor: {}",
            e
        );
    }
}

fn server_read_message<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<Message, MessageDeserializeError> {
    let result = common::read_message(reader);
    if let Err(MessageDeserializeError {
        error_type: MessageDeserializeErrorType::VeryLargeLength,
        ..
    }) = result
    {
        handle_capacity_response(writer);
    }

    result
}

fn handle_shared_secret_file(secret: &SharedSecret) {
    let mut grading_file = match File::create(Args::parse().secret_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Unable to create shared secret grading file because of error {e}");
            return;
        }
    };

    let encoded_secret = BASE64_STANDARD.encode(secret.to_bytes());
    if let Err(e) = grading_file.write_all(encoded_secret.as_bytes()) {
        eprintln!("Unable to write into shared secret grading file because of error {e}");
    }
    if let Err(e) = grading_file.flush() {
        eprintln!("Failed to flush shared secret grading file because of error {e}");
    }
}

fn server_negotiate_shared_secret<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key_pair: &KeyPair,
) -> Result<SharedSecret, Box<dyn Error>> {
    let result = common::negotiate_shared_secret(reader, writer, key_pair);

    Ok(match result {
        Err(ref e) => {
            if let Some(MessageDeserializeError {
                error_type: MessageDeserializeErrorType::VeryLargeLength,
                ..
            }) = e.downcast_ref::<MessageDeserializeError>()
            {
                handle_capacity_response(writer);
            } else {
                eprintln!("{e}");
            }
            return result;
        }
        Ok(s) => {
            handle_shared_secret_file(&s);
            s
        }
    })
}

#[derive(Debug, EnumString)]
enum ServerError {
    InputKeyNotLongEnough,
}
impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
    }
}
impl Error for ServerError {}

fn get_key_pair() -> Result<KeyPair, Box<dyn Error>> {
    Ok(match Args::parse().key {
        Some(v) => {
            let decoded = BASE64_STANDARD.decode(v)?;
            let key_bytes = KeyBytes::try_from(decoded.as_slice())?;
            KeyPair::from_key_bytes(&key_bytes)
        }
        None => KeyPair::new(),
    })
}

fn accept_connection<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key_pair: &KeyPair,
) -> Result<(), Box<dyn Error>> {
    let shared_secret = server_negotiate_shared_secret(reader, writer, key_pair)?;

    loop {
        // We're not interested in the incoming message.
        let _msg = server_read_message(reader, writer)?.dec(&shared_secret)?;
    }
}

fn split_socket_and_accept(stream: TcpStream, key_pair: &KeyPair) -> Result<(), Box<dyn Error>> {
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;

    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    accept_connection(&mut reader, &mut writer, key_pair)?;
    writer.flush()?;
    stream.shutdown(Shutdown::Both)?;

    Ok(())
}

fn main_inner() -> Result<(), Box<dyn Error>> {
    let key_pair = get_key_pair()?;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", PORT))?;

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = split_socket_and_accept(s, &key_pair) {
                    eprintln!("ERROR: Error in accept handler: {}", e);
                }
            }
            Err(e) => eprintln!("ERROR: Error on accept: {}", e),
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let result = main_inner();
    if let Err(ref e) = result {
        eprintln!("{}", e);
    }
    result
}
