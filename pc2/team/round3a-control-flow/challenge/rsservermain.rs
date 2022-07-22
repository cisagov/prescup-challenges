// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

mod opcodes;

use std::fs;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Instant;

use rand::RngCore;
use std::io::{Read, Write};

const STEPS: u32 = 50;
const PORT: u16 = 12345;

enum ResponseType {
    ValuePair(u32, u32),
    Flag(String),
    FlagNotStarted,
    TimedOut,
    IncorrectValue,
    InvalidOpcode,
    NeedsReset,
    ResetAck,
}

enum SubmissionSuccess {
    NewPair(u32, u32),
    Complete,
}

enum SubmissionError {
    FlagNotStarted,
    TimedOut,
    IncorrectValue,
    NeedsReset,
}

#[derive(Clone)]
enum FlagState {
    NotFailed,
    Failed,
}

#[derive(Clone)]
struct GameState {
    timer: Option<Instant>,
    last_value1: u32,
    last_value2: u32,
    steps_taken: u32,
    flag_state: FlagState,
}

impl GameState {
    fn new() -> Self {
        let (value1, value2) = Self::generate_values();
        Self {
            timer: None,
            last_value1: value1,
            last_value2: value2,
            steps_taken: 0,
            flag_state: FlagState::NotFailed,
        }
    }

    fn reset(&mut self) -> (u32, u32) {
        let new_state = Self::new();
        self.clone_from(&new_state);
        (self.last_value1, self.last_value2)
    }

    fn generate_values() -> (u32, u32) {
        (rand::thread_rng().next_u32(), rand::thread_rng().next_u32())
    }

    fn start_flag(&mut self) -> (u32, u32) {
        if let Some(_) = self.timer {
            self.reset();
        }
        self.timer = Some(Instant::now());
        (self.last_value1, self.last_value2)
    }

    fn submit(&mut self, value: u32) -> Result<SubmissionSuccess, SubmissionError> {
        if let FlagState::Failed = self.flag_state {
            return Err(SubmissionError::NeedsReset);
        }
        match self.timer {
            Some(t) => {
                if t.elapsed().as_millis() > 2000 {
                    self.flag_state = FlagState::Failed;
                    return Err(SubmissionError::TimedOut);
                }
            }
            None => return Err(SubmissionError::FlagNotStarted),
        }
        if self.last_value1 * self.last_value2 == value {
            return match self.steps_taken < STEPS {
                true => {
                    let (new_value1, new_value2) = Self::generate_values();
                    self.last_value1 = new_value1;
                    self.last_value2 = new_value2;
                    self.steps_taken += 1;
                    self.timer = Some(Instant::now());
                    Ok(SubmissionSuccess::NewPair(new_value1, new_value2))
                }
                false => Ok(SubmissionSuccess::Complete),
            };
        }
        self.flag_state = FlagState::Failed;
        Err(SubmissionError::IncorrectValue)
    }
}

fn retrieve_flag() -> String {
    match fs::read_to_string("flag.txt") {
        Ok(f) => f.trim().to_string(),
        Err(e) => format!(
            "Error on retrieving your flag. Please report this error (with the \
        error message) to support: {}",
            e.to_string()
        ),
    }
}

fn prepare_response(resp_type: ResponseType) -> Vec<u8> {
    use ResponseType as Resp;
    match resp_type {
        Resp::ValuePair(v1, v2) => {
            let mut out_bytes = vec![0, 0, 0, 0];
            out_bytes.extend_from_slice(&v1.to_le_bytes());
            out_bytes.extend_from_slice(&v2.to_le_bytes());
            out_bytes
        }
        Resp::ResetAck => vec![1, 1, 1, 1],
        Resp::TimedOut => vec![2, 2, 2, 2],
        Resp::FlagNotStarted => vec![3, 3, 3, 3],
        Resp::IncorrectValue => vec![4, 4, 4, 4],
        Resp::Flag(f) => {
            let mut out_bytes = vec![5, 5, 5, 5];
            out_bytes.extend(f.into_bytes());
            out_bytes
        },
        Resp::NeedsReset => vec![6, 6, 6, 6],
        Resp::InvalidOpcode => vec![255, 255, 255, 255],
    }
}

fn handle_client(mut stream: TcpStream, game_state: &mut GameState) {
    use opcodes::OpcodeResult as Op;
    use ResponseType as Resp;
    use SubmissionError as Fail;

    let mut in_bytes = Vec::new();
    match stream.read_to_end(&mut in_bytes) {
        Ok(_) => (),
        Err(_) => {
            stream
                .shutdown(Shutdown::Both)
                .expect("Got a socket read error.");
            return;
        }
    }

    let response = match opcodes::interpret_opcode(in_bytes) {
        Op::ResetCode => {
            game_state.reset();
            Resp::ResetAck
        }
        Op::StartCode => {
            let (v1, v2) = game_state.start_flag();
            Resp::ValuePair(v1, v2)
        }
        Op::SubmitCode { value } => match game_state.submit(value) {
            Ok(s) => match s {
                SubmissionSuccess::NewPair(v1, v2) => Resp::ValuePair(v1, v2),
                SubmissionSuccess::Complete => Resp::Flag(retrieve_flag()),
            },
            Err(f) => match f {
                Fail::FlagNotStarted => Resp::FlagNotStarted,
                Fail::IncorrectValue => Resp::IncorrectValue,
                Fail::TimedOut => Resp::TimedOut,
                Fail::NeedsReset => Resp::NeedsReset,
            },
        },
        Op::InvalidCode => Resp::InvalidOpcode,
    };

    let out_bytes = prepare_response(response);
    if let Err(_) = stream.write_all(out_bytes.as_slice()) {
        stream
            .shutdown(Shutdown::Both)
            .expect("Got a socket write error.");
    };
}

fn main() {
    let mut game_state = GameState::new();
    let listener = TcpListener::bind(format!("0.0.0.0:{}", PORT)).unwrap();

    println!("Listening on port {}...", PORT);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                println!("Accepted connection from {}...", s.peer_addr().unwrap());
                handle_client(s, &mut game_state);
            },
            Err(e) => println!("Error on accept: {}", e.to_string()),
        }
    }
}
