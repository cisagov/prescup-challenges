// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

const RESET_CODE: u8 = 1 << 0;
const START_CODE: u8 = 1 << 1;
const SUBMIT_CODE: u8 = 1 << 2;

pub enum OpcodeResult {
    ResetCode,
    StartCode,
    SubmitCode { value: u32 },
    InvalidCode,
}

pub fn interpret_opcode(data: Vec<u8>) -> OpcodeResult {
    println!("Got array: {:?}", data);
    use OpcodeResult::*;
    let code = match data.get(0) {
        Some(c) => *c,
        None => return InvalidCode,
    };
    println!("Got opcode: {}", code);

    match code {
        RESET_CODE => ResetCode,
        START_CODE => StartCode,
        SUBMIT_CODE => {
            if data.len() != 5 {
                println!(
                    "Rejecting submit attempt because the data length was not the expected \
                size."
                );
                return InvalidCode;
            }
            let mut submit_array = [0u8; 4];
            for (i, &byte) in data[1..].iter().enumerate() {
                submit_array[i] = byte;
            }
            let value = u32::from_le_bytes(submit_array);
            SubmitCode { value }
        }
        _ => InvalidCode,
    }
}
