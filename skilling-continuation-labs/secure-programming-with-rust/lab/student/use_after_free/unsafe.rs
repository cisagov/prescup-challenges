
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use std::alloc::{Layout, alloc, dealloc};

fn main() {
    let mem_layout = Layout::array::<i32>(1000).unwrap();

    let int_arr;
    unsafe {
        int_arr = alloc(mem_layout).cast::<i32>();
    }

    for i in 0..1000 {
        unsafe {
            *int_arr.add(i) = i as i32;
        }
    }

    println!("\nValue located at the tenth index of integer array 'int_arr': {}", unsafe { *int_arr.add(10) });

    unsafe {
        dealloc(int_arr.cast::<u8>(), mem_layout);
    }

    println!("Value located at the tenth index of array after deallocating it: {}", unsafe { *int_arr.add(10) });
}
