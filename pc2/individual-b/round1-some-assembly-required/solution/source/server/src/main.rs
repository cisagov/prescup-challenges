// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#[macro_use]
extern crate rocket;

use std::fs::OpenOptions;
use std::io::Write;

use rocket::Data;
use rocket::data::ByteUnit;

static SIGNATURES: &[&[u8]] = &[
    &[
        0x60, 0x89, 0xe5, 0x31, 0xc0, 0x64, 0x8b, 0x50, 0x30, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x14,
    ],
    &[0x8b, 0x72, 0x28, 0x0f, 0x0b7, 0x4a, 0x26, 0x31, 0xff],
    &[0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20],
    &[
        0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xe2, 0xf2, 0x52, 0x57, 0x8b, 0x52, 0x10, 0x8b, 0x4a, 0x3c,
        0x8b, 0x4c, 0x11, 0x78,
    ],
    &[
        0xe3, 0x48, 0x01, 0xd1, 0x51, 0x8b, 0x59, 0x20, 0x01, 0xd3, 0x8b, 0x49, 0x18,
    ],
    &[0xe3, 0x3a, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xd6, 0x31, 0xff],
    &[
        0xac, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0x38, 0xe0, 0x75, 0xf6, 0x03, 0x7d, 0xf8, 0x3b, 0x7d,
        0x24, 0x75, 0xe4,
    ],
    &[
        0x58, 0x8b, 0x58, 0x24, 0x01, 0xd3, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x58, 0x1c, 0x01, 0xd3,
        0x8b, 0x04, 0x8b,
    ],
    &[
        0x01, 0xd0, 0x89, 0x44, 0x24, 0x24, 0x5b, 0x5b, 0x61, 0x59, 0x5a, 0x51, 0xff, 0xe0,
    ],
    &[
        0x5d, 0x68, 0x33, 0x32, 0x00, 0x00, 0x68, 0x77, 0x73, 0x32, 0x5f, 0x54, 0x68, 0x4c, 0x77,
        0x26, 0x07, 0x89, 0xe8,
    ],
];
const MIN_SIGNATURES: usize = 2;
const MAX_SIGNATURES: usize = 7;

const SIGNATURE_FLAGS: &[&str] = &[
    "e631f3d34ea24c29",
    "d62aee17dcad9c49",
    "b4bb357b07b174ab",
    "7b9f21198846001a",
];
const INVALID_VARIANT: &str = "INVALID VARIANT, PLEASE REPORT";

fn get_variant() -> Option<u8> {
    // Modified for open source
    return Some(1);
}

fn get_flag() -> String {
    match get_variant() {
        Some(v) => SIGNATURE_FLAGS[v as usize - 1].to_string(),
        None => INVALID_VARIANT.to_string(),
    }
}

fn log_message(mut message: String) {
    let mut file = match OpenOptions::new()
        .append(true)
        .create(true)
        .open("prescup_b5_i1_log.txt")
    {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open log file: {}", e);
            return;
        }
    };
    message.push('\n');
    match file.write(message.as_bytes()) {
        Ok(_) => (),
        Err(e) => println!("Unable to write to log file: {}", e),
    };
}

enum SignatureResult {
    NotEnoughBroken,
    EnoughBroken,
    TooManyBroken,
}

fn check_signatures(contents: &[u8]) -> SignatureResult {
    let mut found = false;
    let mut found_count = 0;
    for &sig in SIGNATURES.iter() {
        for window in contents.windows(sig.len()) {
            if sig == window {
                log_message(format!("Found signature: {:x?}", sig));
                found = true;
                found_count += 1;
                // Make sure to only count a signature once. In theory a given signature should be
                // a long enough byte sequence to be unique in the executable, but just to be sure,
                // cut it off here.
                break;
            }
        }
        if found == false {
            log_message(format!("Did not find: {:x?}", sig));
        }
        found = false;
    }

    log_message(format!(
        "Found {} out of {} signatures",
        found_count,
        SIGNATURES.len()
    ));

    use SignatureResult::*;
    let broken_signatures = SIGNATURES.len() - found_count;
    if broken_signatures < MIN_SIGNATURES {
        return NotEnoughBroken;
    } else if broken_signatures <= MAX_SIGNATURES {
        return EnoughBroken;
    }
    TooManyBroken
}

#[post("/", data = "<file>")]
async fn upload(file: Data<'_>) -> Result<String, std::io::Error> {
    let data = file.open(ByteUnit::GB);
    let data_buf = match data.into_bytes().await {
        Ok(v) => v.to_vec(),
        Err(e) => {
            log_message(format!("read_to_end error: {}", e));
            return Ok(
                "\nThe server encountered an error with your upload. Please report this."
                    .to_string(),
            );
        }
    };

    match check_signatures(&data_buf) {
        SignatureResult::TooManyBroken => Ok("\nToo many broken signatures.\n".to_string()),
        SignatureResult::NotEnoughBroken => Ok("\nNot enough broken signatures.\n".to_string()),
        SignatureResult::EnoughBroken => {
            let flag = get_flag();
            // Does not check validity for now, but maybe that's fine since the simplest solution
            // is to just insert a few NOP instructions anyway. The point of the exercise is to
            // demonstrate that signature checking should not be your only defense. This also
            // makes it a bit more forgiving for people who know a little bit of assembly, but
            // might not know enough to ensure that the program still functions.
            Ok(format!(
                "\nSuccess! Here is your flag: prescup{{{}}}\n",
                flag
            ))
        }
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![upload])
}
