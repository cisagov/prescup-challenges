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

#[macro_use]
extern crate rocket;

mod f64_wrapper;

use std::{net::IpAddr, process::Command, str::FromStr};

use crate::f64_wrapper::F64;

use log::{error, info};
use rocket::{serde::json::Json, Config};
use schemars::{schema::RootSchema, schema_for, JsonSchema};
use serde::Deserialize;

enum Sign {
    Positive = 0,
    Negative = 1,
}
impl From<u64> for Sign {
    fn from(value: u64) -> Self {
        match value & 1 {
            0 => Self::Positive,
            1 => Self::Negative,
            _ => unreachable!(),
        }
    }
}

const EXP_LEN: usize = 11;
struct Exponent([u8; EXP_LEN]);
impl From<u64> for Exponent {
    fn from(value: u64) -> Self {
        let mut bits = [0u8; EXP_LEN];

        for i in 0..EXP_LEN {
            bits[bits.len() - i - 1] = (value >> i & 1) as u8;
        }

        Self(bits)
    }
}
impl From<[u8; EXP_LEN]> for Exponent {
    fn from(value: [u8; EXP_LEN]) -> Self {
        let mut bits = [0u8; EXP_LEN];

        for i in 0..EXP_LEN {
            bits[i] = value[i];
        }

        Self(bits)
    }
}

const MANT_LEN: usize = 52;
struct Mantissa([u8; MANT_LEN]);
impl From<u64> for Mantissa {
    fn from(value: u64) -> Self {
        let mut bits = [0u8; MANT_LEN];

        for i in 0..MANT_LEN {
            bits[bits.len() - i - 1] = (value >> i & 1) as u8;
        }

        Self(bits)
    }
}
impl From<[u8; MANT_LEN]> for Mantissa {
    fn from(value: [u8; MANT_LEN]) -> Self {
        let mut bits = [0u8; MANT_LEN];

        for i in 0..MANT_LEN {
            bits[i] = value[i];
        }

        Self(bits)
    }
}

fn construct_f64(sign: Sign, exponent: Exponent, mantissa: Mantissa) -> f64 {
    let sign = (sign as u64) << 63;
    let exponent = exponent.0.iter().fold(0u64, |acc, b| acc << 1 | *b as u64) << 52;
    let mantissa = mantissa.0.iter().fold(0u64, |acc, b| acc << 1 | *b as u64);

    f64::from_bits(sign | exponent | mantissa)
}

fn display_f64_bits(value: f64) {
    let bits: u64 = value.to_bits();
    let sign = (bits >> 63) & 1;
    let exponent = (bits >> 52) & 0x7FF;
    let mantissa = bits & 0xFFFFFFFFFFFFF;

    info!("####################");
    info!("Value: {}", value);
    info!("Bits: {:#066b}", bits);

    info!("display_f64_bits:");
    info!("Sign bit     : {}", sign);
    info!(
        "Exponent bits: {:#013b} (unbiased: {})",
        exponent,
        exponent as i16 - 1023
    );
    info!("Mantissa bits: {:#053b}", mantissa);

    info!(
        "Back in its original form: {}",
        construct_f64(sign.into(), exponent.into(), mantissa.into())
    );
    info!("####################");
}

#[derive(Deserialize, JsonSchema)]
struct PartDataf64 {
    value1: f64,
    value2: f64,
}

impl From<PartDataf64> for (F64, F64) {
    fn from(value: PartDataf64) -> Self {
        (value.value1.into(), value.value2.into())
    }
}

#[derive(Clone, Copy, Debug)]
enum Part {
    P1 = 1,
    P2 = 2,
    P3 = 3,
    P4 = 4,
}

impl Part {
    fn get_part_token(&self) -> Result<String, ()> {
        let guestinfo_arg = format!("info-get guestinfo.token{}", *self as i32);
        let result = Command::new("vmtoolsd")
            .args(["--cmd", guestinfo_arg.as_str()])
            .output();

        let result_out = match result {
            Ok(v) => v,
            Err(e) => {
                error!("vmtoolsd command failed with error: {}", e);
                return Err(());
            }
        };

        let result_str = match String::from_utf8(result_out.stdout) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Result from vmtoolsd command could not be parsed as a UTF-8 string: {}",
                    e
                );
                return Err(());
            }
        };

        let token = result_str.trim();
        if token.is_empty() {
            error!("Result from vmtoolsd command was empty.");
            return Err(());
        }

        Ok(token.to_string())
    }
}

fn format_f64(value: f64) -> String {
    let value_trunc = format!("{value:.1}");
    let value_str = format!("{value}");

    if value_trunc.len() < value_str.len() {
        value_str
    } else {
        value_trunc
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PartCorrect {
    Correct,
    Incorrect,
}

fn handle_part(expected: f64, from_user_input: f64, part: Part) -> (PartCorrect, String) {
    use PartCorrect::*;

    display_f64_bits(expected);
    display_f64_bits(from_user_input);

    let expected_bits = expected.to_bits();
    let user_input_bits = from_user_input.to_bits();
    if expected_bits == user_input_bits {
        let out_string = match part.get_part_token() {
            Ok(v) => v,
            Err(_) => "Unable to retrieve token. Please contact support.".to_string(),
        };

        return (Correct, out_string);
    }

    let width = 64;

    let expected_string = format!(
        "Expected:    {expected_bits:0width$b} (Value: {})",
        format_f64(expected)
    );
    let user_input_string = format!(
        "Given input: {user_input_bits:0width$b} (Value: {})",
        format_f64(from_user_input)
    );

    (
        Incorrect,
        format!(
            "Input values did not combine to match the expected bit pattern.\n{}\n{}",
            expected_string, user_input_string
        ),
    )
}

fn part1_callee(part_data: PartDataf64) -> (PartCorrect, String) {
    let (v1, v2) = part_data.into();

    handle_part(f64::INFINITY, (v1 + v2).into(), Part::P1)
}

#[post("/part1", format = "application/json", data = "<part_data>")]
fn part1(part_data: Json<PartDataf64>) -> String {
    let (_, res) = part1_callee(part_data.into_inner());
    res
}

fn part2_callee(part_data: PartDataf64) -> (PartCorrect, String) {
    let (v1, v2) = part_data.into();

    // dev build profile handles this differently from release profile.
    // I think it's opt-level. In dev mode, using 0.0 and 9.785 for v1
    // and v2 resulted in a negative NAN. In release mode, it was a
    // positive. So I used copysign to force the sign to positive to
    // work around this edge case.
    let user_value: f64 = (v1 / (v2 - 9.785)).into();

    handle_part(f64::NAN, user_value.copysign(0.0), Part::P2)
}

#[post("/part2", format = "application/json", data = "<part_data>")]
fn part2(part_data: Json<PartDataf64>) -> String {
    let (_, res) = part2_callee(part_data.into_inner());
    res
}

fn part3_callee(part_data: PartDataf64) -> (PartCorrect, String) {
    let (v1, v2) = part_data.into();

    handle_part(f64::INFINITY, (v1 << v2).into(), Part::P3)
}

#[post("/part3", format = "application/json", data = "<part_data>")]
fn part3(part_data: Json<PartDataf64>) -> String {
    let (_, res) = part3_callee(part_data.into_inner());
    res
}

fn part4_callee(part_data: PartDataf64) -> (PartCorrect, String) {
    let (v1, v2) = part_data.into();

    handle_part(f64::NEG_INFINITY, (v1 ^ v2).into(), Part::P4)
}

#[post("/part4", format = "application/json", data = "<part_data>")]
fn part4(part_data: Json<PartDataf64>) -> String {
    let (_, res) = part4_callee(part_data.into_inner());
    res
}

fn solution_part1() {
    let part_data = PartDataf64 {
        value1: 1e308,
        value2: 1e308,
    };

    info!("Checking Part 1 correctness...");

    let (cor, res) = part1_callee(part_data);

    assert_eq!(PartCorrect::Correct, cor, "{}", res);
}

fn solution_part2() {
    let part_data = PartDataf64 {
        value1: 0.0,
        value2: 9.785,
    };

    info!("Checking Part 2 correctness...");

    let (cor, res) = part2_callee(part_data);

    assert_eq!(PartCorrect::Correct, cor, "{}", res);
}

fn solution_part3() {
    let part_data = PartDataf64 {
        value1: 1.5,
        value2: 5e-324,
    };

    info!("Checking Part 3 correctness...");

    let (cor, res) = part3_callee(part_data);

    assert_eq!(PartCorrect::Correct, cor, "{}", res);
}

fn solution_part4() {
    let part_data = PartDataf64 {
        value1: -1.0,
        value2: 2.0,
    };

    info!("Checking Part 4 correctness...");

    let (cor, res) = part4_callee(part_data);

    assert_eq!(PartCorrect::Correct, cor, "{}", res);
}

#[get("/schema")]
fn get_schema() -> Json<RootSchema> {
    Json(schema_for!(PartDataf64))
}

#[launch]
fn rocket() -> _ {
    env_logger::init();

    // Assert that all parts have a valid solution to
    // ensure that if the server starts, all is well.
    solution_part1();
    solution_part2();
    solution_part3();
    solution_part4();

    let mut config = Config::default();
    config.address = IpAddr::from_str("0.0.0.0").unwrap();

    rocket::custom(&config).mount("/", routes![part1, part2, part3, part4, get_schema])
}
