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

use std::{
    error::Error,
    io::{BufReader, BufWriter},
    net::TcpStream,
    thread,
    time::Duration,
};

mod common;
use clap::Parser;
use common::{KeyPair, Message, PORT};
use rand::{self, Rng};

#[derive(Debug, Parser)]
struct ClientArgs {
    /// Connect to localhost for testing.
    #[arg(short)]
    test_mode: bool,
}

fn connect(server: &str) -> Result<(), Box<dyn Error>> {
    let key_pair = KeyPair::new();
    let stream = TcpStream::connect(format!("{}:{}", server, PORT))?;
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    let shared_secret = common::negotiate_shared_secret(&mut reader, &mut writer, &key_pair)?;

    loop {
        let data = rand::thread_rng().gen::<[u8; 32]>();
        let msg = Message::new(&data).enc(&shared_secret)?;
        common::write_message(&mut writer, &msg)?;
        thread::sleep(Duration::from_millis(500));
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let server = match ClientArgs::parse().test_mode {
        true => "localhost",
        false => "challenge.us",
    };

    connect(server)?;

    Ok(())
}
