
// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#![allow(unused)]
use std::cmp::Ordering::Equal;
use std::fs;
use std::io;

use dirs;
use pyo3::prelude::*;

// one: e27a8e3c4da0d524
// two: bc1a09992533a144
// three: ed62496c14454767
// four: 9089dddcfa3b75be

const XOR: [u8; 16] = [
    97, 216, 250, 172, 217, 192, 9, 244, 5, 146, 44, 222, 118, 16, 149, 16,
];
const CIPHER: [u8; 16] = [
    88, 232, 194, 149, 189, 164, 109, 151, 99, 243, 31, 188, 65, 37, 247, 117,
];

/// You're gonna want to examine the assembly for this one...
/// Well okay, "want" is probably not accurate, but you get the idea.
#[pyfunction]
fn four(a: u64, b: &str, c: f32) -> PyResult<String> {
    if a != 329875398726 {
        return Ok("Failed on first argument".to_string());
    }
    if b.cmp("vblvljken") != Equal {
        return Ok("Failed on second argument".to_string());
    }
    if c != 299792.458 {
        return Ok("Failed on third argument".to_string());
    }
    let flag_bytes = XOR.iter().zip(CIPHER).map(|(&x, c)| x ^ c).collect();
    Ok(String::from_utf8(flag_bytes)?)
}

#[pymodule]
fn mainmodule(py: Python, m: &PyModule) -> PyResult<()> {
    Python::with_gil(|py| -> PyResult<()> {
        let module = PyModule::from_code(
            py,
            obfstr::obfstr!(
                r###"
import random


class ExamineMe:
    one = "e27a8e3c4da0d524"

def decode_or_not(stuff, work=False):
    return work

def two():
    """ This function calls decode_or_not, but then doesn't provide an argument.
    Can you fix it?
    """
    a = [107, 205, 127, 101, 201, 99, 121, 207, 76, 227, 213, 70, 65, 49, 112, 83]
    b = [90, 175, 28, 80, 253, 80, 64, 252, 117, 211, 236, 119, 32, 5, 17, 97]
    l = [13, 0, 1, 9, 15, 10, 6, 11, 7, 4, 5, 2, 3, 14, 12, 8]
    e = [None]*16
    x = [None]*16
    if decode_or_not('haha'):
        for i, idx in enumerate(l):
            e[idx] = a[i]
            x[idx] = b[i]
        o = []
        for i, j in zip(e, x):
            o.append(i ^ j)
        return ''.join(map(chr, o))

def three(a, b, c, d):
    """ Examine this function's bytecode and map out the arguments to get the token. Alternatively,
    use the bytecode to piece the token together yourself.
    """
    i = [252, 199, 208, 147, 137, 254, 65, 227, 58, 205, 53, 216, 192, 143, 239, 182]
    j = [202, 164, 228, 164, 237, 202, 36, 218, 12, 251, 0, 236, 244, 184, 221, 135]
    k = [6, 4, 8, 14, 2, 7, 0, 1, 15, 11, 5, 10, 12, 3, 9, 13]
    l = [None]*16
    m = [None]*16
    if a != 2*d:
        return
    if b < 4*a:
        return
    if c != 8*b:
        return
    if decode_or_not("you thought you had seen the last of me!"):
        return
    if d != "8675309":
        return
    for p, idx in enumerate(k):
        l[idx] = i[p]
        m[idx] = j[p]
    n = []
    for q, r in zip(l, m):
        n.append(q ^ r)
    return ''.join(map(chr, n))
"###
            ),
            "lookinhere.py",
            "lookinhere",
        )?;
        module.add_function(wrap_pyfunction!(four, module)?)?;
        m.add_submodule(module);
        Ok(())
    })?;

    Ok(())
}

