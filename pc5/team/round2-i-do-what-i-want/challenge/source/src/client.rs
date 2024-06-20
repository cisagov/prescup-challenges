
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// use crate::common::Mode;
use crate::common::{
    get_password, get_username, read_message, write_message, LoginError, Operation, LOGIN_FAILURE,
    LOGIN_SUCCESS,
};
use std::{
    env,
    io::{BufReader, BufWriter, Read, Write},
    net::{Shutdown, TcpStream},
    str::FromStr,
};

use anyhow::Result as AnyhowResult;

mod common;

fn send_login_request<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> AnyhowResult<()> {
    write_message(writer, &get_username())?;
    write_message(writer, &get_password())?;
    writer.flush()?;

    let mut in_string = String::new();
    read_message(reader, &mut in_string)?;

    if in_string.trim() != LOGIN_SUCCESS {
        eprint!("{}", LOGIN_FAILURE);
        return Err(LoginError {}.into());
    }

    Ok(())
}

fn parse_ops(op_1: &str, operation: &str, op_2: &str) -> AnyhowResult<(i32, Operation, i32)> {
    let op_1 = op_1.parse()?;
    let operation = Operation::from_str(operation)?;
    let op_2 = op_2.parse()?;

    Ok((op_1, operation, op_2))
}

fn handle_single_challenge<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> AnyhowResult<()> {
    let mut in_string = String::new();

    read_message(reader, &mut in_string)?;

    let mut splitter = in_string.split_whitespace();
    let (op_1, operation, op_2) = parse_ops(
        splitter.next().unwrap_or_else(|| ""),
        splitter.next().unwrap_or_else(|| ""),
        splitter.next().unwrap_or_else(|| ""),
    )?;

    let answer = operation.perform_operation(op_1, op_2);

    write_message(writer, &answer.to_string())?;

    Ok(())
}

fn handle_math_challenges<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> AnyhowResult<()> {
    for _ in 0..30 {
        handle_single_challenge(reader, writer)?;
    }

    Ok(())
}

fn connect_read_loop_body(server: &str) -> AnyhowResult<()> {
    let stream = TcpStream::connect(format!("{}:{}", server, common::PORT))?;
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    send_login_request(&mut reader, &mut writer)?;
    println!("{}", LOGIN_SUCCESS);

    handle_math_challenges(&mut reader, &mut writer)?;
    println!("Arithmetic questions all solved.");

    // Wait for the server to close the connection to avoid the ugly "failed to fill buffer" error.
    let mut buf = vec![];
    reader.read_to_end(&mut buf)?;

    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn main() {
    let server = match env::args().find(|e| e == "--test") {
        Some(_) => "localhost",
        None => "challenge.us",
    };

    if let Err(e) = connect_read_loop_body(server) {
        eprintln!("{}", e);
    }
}

