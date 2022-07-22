
// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

pub mod endpoints {

    use rand::seq::SliceRandom;
    use rand::thread_rng;

    use rocket::serde::json::Json;
    use rocket::serde::{Deserialize, Serialize};

    const FIRST_GIVEN_SEQ_LEN: usize = 16;
    const FIRST_RESP_SEQ_LEN: usize = 16;
    const SECOND_GIVEN_SEQ_LEN: usize = 32;
    const SECOND_RESP_SEQ_LEN: usize = 32;
    const THIRD_GIVEN_SEQ_LEN: usize = 255;
    const THIRD_RESP_SEQ_LEN: usize = 1;

    use crate::helpers::misc::get_flag;
    use crate::helpers::{math_funcs, misc};
    use std::num::ParseFloatError;

    lazy_static! {
        static ref THIRD_SEQUENCE: Vec<u8> = {
            let mut sequence: Vec<u8> = (0..=255).collect();
            let mut rng = thread_rng();
            sequence.shuffle(&mut rng);
            sequence
        };
    }
    const FAILURE_STRING: &str = "Formatting was correct, but sequence was not.";

    #[derive(Serialize, Deserialize)]
    #[serde(crate = "rocket::serde")]
    pub struct Message<T> {
        resp_len: Option<usize>,
        sequence: Vec<T>,
    }

    #[get("/first")]
    pub fn first() -> Json<Message<i8>> {
        Json(Message {
            resp_len: Some(FIRST_RESP_SEQ_LEN),
            sequence: math_funcs::fibonacci().take(FIRST_GIVEN_SEQ_LEN).collect(),
        })
    }

    #[post("/first", format = "json", data = "<submission>")]
    pub fn first_submit(submission: Json<Message<i8>>) -> String {
        let numbers: Vec<i8> = math_funcs::fibonacci()
            .skip(FIRST_GIVEN_SEQ_LEN)
            .take(FIRST_RESP_SEQ_LEN)
            .collect();
        match submission.sequence == numbers {
            true => misc::get_flag(1),
            false => FAILURE_STRING.to_string(),
        }
    }

    #[get("/second")]
    pub fn second() -> Json<Message<f64>> {
        Json(Message {
            resp_len: Some(SECOND_RESP_SEQ_LEN),
            sequence: math_funcs::shifted_floats()
                .take(SECOND_GIVEN_SEQ_LEN)
                .collect(),
        })
    }

    fn parse_doubles<'a>(
        seq: impl Iterator<Item = &'a String>,
    ) -> Result<Vec<f64>, ParseFloatError> {
        let mut out = Vec::new();
        for value in seq {
            match value.parse::<f64>() {
                Ok(v) => out.push(v),
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    #[post("/second", format = "json", data = "<submission>")]
    pub fn second_submit(submission: Json<Message<String>>) -> String {
        let numbers: Vec<f64> = math_funcs::shifted_floats()
            .skip(SECOND_GIVEN_SEQ_LEN)
            .take(SECOND_RESP_SEQ_LEN)
            .collect();
        let submitted = match parse_doubles(submission.sequence.iter()) {
            Ok(parsed) => parsed,
            Err(e) => return e.to_string(),
        };
        match numbers == submitted {
            true => misc::get_flag(2),
            false => FAILURE_STRING.to_string(),
        }
    }

    #[get("/third")]
    pub fn third() -> Json<Message<u8>> {
        Json(Message {
            resp_len: Some(THIRD_RESP_SEQ_LEN),
            sequence: THIRD_SEQUENCE
                .iter()
                .take(THIRD_GIVEN_SEQ_LEN)
                .map(|n| *n)
                .collect(),
        })
    }

    #[post("/third", format = "json", data = "<submission>")]
    pub fn third_submit(submission: Json<Message<u8>>) -> String {
        match submission
            .sequence
            .iter()
            .rev()
            .take(THIRD_RESP_SEQ_LEN)
            .collect::<Vec<_>>()
            == THIRD_SEQUENCE
                .iter()
                .rev()
                .take(THIRD_RESP_SEQ_LEN)
                .collect::<Vec<_>>()
        {
            true => get_flag(3),
            false => FAILURE_STRING.to_string(),
        }
    }
}

