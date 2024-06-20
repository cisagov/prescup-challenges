
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

mod common;

// use lazy_static::lazy_static;
// use rand::Rng;

use crate::common::{
    get_password, get_username, read_message, read_message_timeout_ok, write_message, LoginError,
    Operation, LOGIN_FAILURE, LOGIN_SUCCESS,
};
use std::{
    error::Error,
    fmt::Display,
    io::{BufReader, BufWriter, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    process::Command,
    time::Duration,
};

use anyhow::Result as AnyhowResult;

const TOKEN_2: &str = include_str!("token2");
const TOKEN_3: &str = include_str!("token3");

fn validate_login<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> AnyhowResult<()> {
    let mut in_string = String::new();

    read_message(reader, &mut in_string)?;
    println!("Got '{}' as client username.", in_string);
    if in_string != get_username() {
        eprintln!(
            "Username match failed. Server was expecting {} as a username.",
            get_username()
        );
        write_message(writer, LOGIN_FAILURE)?;
        return Err(LoginError {}.into());
    }

    read_message(reader, &mut in_string)?;
    println!("Got '{}' as client password.", in_string);
    if in_string != get_password() {
        eprintln!(
            "Password match failed. Server was expecting {} as a password.",
            get_password()
        );
        write_message(writer, LOGIN_FAILURE)?;
        return Err(LoginError {}.into());
    }

    write_message(writer, LOGIN_SUCCESS)?;
    println!("Wrote {} back to client.", LOGIN_SUCCESS);

    Ok(())
}

fn knock_knock<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> AnyhowResult<()> {
    let mut in_string = String::new();

    read_message_timeout_ok(reader, &mut in_string)?;

    if in_string == "knock knock" {
        write_message(writer, TOKEN_2)?;
    }

    Ok(())
}

#[derive(Debug)]
struct IncorrectChallengeResponse {
    msg: String,
}
impl Display for IncorrectChallengeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}
impl Error for IncorrectChallengeResponse {}

fn single_challenge<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> AnyhowResult<()> {
    let mut client_message = String::new();

    let operation = Operation::random();
    let (op_1, op_2) = operation.generate_operands();
    let expected_answer = operation.perform_operation(op_1, op_2);

    let text_representation = format!("{} {} {}", op_1, operation.to_string(), op_2);
    write_message(writer, &text_representation)?;

    read_message(reader, &mut client_message)?;

    let response = match client_message.parse::<i32>() {
        Ok(r) => r,
        Err(_) => {
            let msg = format!("Could not parse your answer into i32: {}", client_message);
            write_message(writer, &msg)?;
            return Err(IncorrectChallengeResponse { msg }.into());
        }
    };

    if expected_answer != response {
        let msg = format!(
            "Answer did not match the expected answer {} for the expression {}.",
            expected_answer, text_representation
        );
        write_message(writer, &msg)?;
        return Err(IncorrectChallengeResponse { msg }.into());
    }

    Ok(())
}

fn math_challenges<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> AnyhowResult<()> {
    let mut client_message = String::new();

    for _ in 0..30 {
        single_challenge(reader, writer)?;
    }

    read_message_timeout_ok(reader, &mut client_message)?;

    if client_message == "one more" {
        single_challenge(reader, writer)?;
        write_message(writer, TOKEN_3)?;
    }

    Ok(())
}

fn accept_connection<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> AnyhowResult<()> {
    println!("Accepted connection");

    println!("Validating login...");
    validate_login(reader, writer)?;

    println!("Checking for knock knock...");
    knock_knock(reader, writer)?;

    println!("Beginning math challenges...");
    math_challenges(reader, writer)?;

    Ok(())
}

fn split_socket_and_accept(stream: TcpStream) -> AnyhowResult<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;

    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    accept_connection(&mut reader, &mut writer)?;
    writer.flush()?;
    stream.shutdown(Shutdown::Both)?;

    Ok(())
}

fn main() {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", common::PORT)).unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = split_socket_and_accept(s) {
                    eprintln!("ERROR: Error in accept handler: {}", e);
                }
            }
            Err(e) => eprintln!("ERROR: Error on accept: {}", e),
        }
    }
}

