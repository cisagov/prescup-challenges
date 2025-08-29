
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use std::{
    error::Error,
    io::{self, Write},
};

fn safe_equivalent_clean() -> Result<(), Box<dyn Error>> {
    let mut password = String::new();
    
    
    if password.trim() == expected_password {
        println!("Access granted!");
    } else {
        println!("Access denied!");
    }

    Ok(())
}

fn main() {
    _ = safe_equivalent_clean();
}


