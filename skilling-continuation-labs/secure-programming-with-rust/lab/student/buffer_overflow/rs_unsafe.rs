
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use std::{
    error::Error,
    io::{self, Read, Write},
};

fn unsafe_equivalent() -> Result<(), Box<dyn Error>> {
    let mut password = [0; 10];
    let expected_password = "password".as_bytes();
    let mut is_authenticated = 0;

    println!("Enter Admin password: ");
    io::stdout().flush()?;
    let mut input_vec = vec![0; 20];
    let _ = io::stdin().read(&mut input_vec)?;
    println!("{input_vec:?}");

    let raw_ptr_password = password.as_mut_ptr();
    for (index, element) in input_vec.iter().enumerate() {
        unsafe {
            *raw_ptr_password.add(index) = *element;
        }
    }
    println!("{password:?}");

    if (0..expected_password.len()).all(|index| password[index] == expected_password[index]) {
        is_authenticated = 1;
    }

    if is_authenticated == 0 {
        println!("Access denied!");
    } else {
        println!("Access granted!");
    }

    Ok(())
}

fn main() {
    _ = unsafe_equivalent();
}


