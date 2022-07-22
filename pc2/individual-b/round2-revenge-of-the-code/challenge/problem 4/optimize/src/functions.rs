// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

pub fn fibo_slow(n: i32) -> i32 {
    if n < 2 {
        return n;
    }

    fibo_slow(n - 1) + fibo_slow(n - 2)
}

// implement this function for challenge completion
pub fn fibo_optimized(n: i32) -> u128 {
    return 0;
}
