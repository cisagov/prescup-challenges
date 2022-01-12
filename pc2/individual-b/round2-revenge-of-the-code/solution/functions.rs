// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// Slow/naive implementation
pub fn fibo_slow(n: i32) -> i32 {
    if n < 2 {
        return n;
    }

    fibo_slow(n - 1) + fibo_slow(n - 2)
}

// Better but not ideal
pub fn fibo_medium(n: i32) -> u128 {
    let mut nums = Vec::new();
    nums.push(0);
    nums.push(1);

    for i in 2..(n+1) {
        nums.push(nums[(i - 1) as usize] + nums[(i - 2) as usize]);
    }

    nums[n as usize]
}

// Optimized version with ~~~ Dynamic Programming ~~~
pub fn fibo_optimized(n: i32) -> u128 {
    let mut minus1 = 1;
    let mut minus2 = 0;
    let mut curr = 0;

    for _ in 2..(n+1) {
        curr = minus1 + minus2;
        minus2 = minus1;
        minus1 = curr
    }

    curr
}