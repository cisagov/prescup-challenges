// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

mod functions;

use std::time::{SystemTime};

fn main() {
    // Tests
    let mut start = SystemTime::now();
    let mut res = functions::fibo_optimized(0);
    let mut elapsed = SystemTime::now().duration_since(start).expect("Error");
    println!("{:?}", elapsed.as_micros());
    println!("{}", 0);
    println!("{}", res);

    start = SystemTime::now();
    res = functions::fibo_optimized(10);
    elapsed = SystemTime::now().duration_since(start).expect("Error");
    println!("{:?}", elapsed.as_micros());
    println!("{}", 10);
    println!("{}", res);

    start = SystemTime::now();
    res = functions::fibo_optimized(25);
    elapsed = SystemTime::now().duration_since(start).expect("Error");
    println!("{:?}", elapsed.as_micros());
    println!("{}", 25);
    println!("{}", res);

    start = SystemTime::now();
    res = functions::fibo_optimized(50);
    elapsed = SystemTime::now().duration_since(start).expect("Error");
    println!("{:?}", elapsed.as_micros());
    println!("{}", 50);
    println!("{}", res);

    start = SystemTime::now();
    res = functions::fibo_optimized(75);
    elapsed = SystemTime::now().duration_since(start).expect("Error");
    println!("{:?}", elapsed.as_micros());
    println!("{}", 75);
    println!("{}", res);

    start = SystemTime::now();
    res = functions::fibo_optimized(100);
    elapsed = SystemTime::now().duration_since(start).expect("Error");
    println!("{:?}", elapsed.as_micros());
    println!("{}", 100);
    println!("{}", res);
}