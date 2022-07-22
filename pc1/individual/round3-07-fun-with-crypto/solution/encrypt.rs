/*
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
*/

extern crate crypto;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crypto::{aes, blockmodes, buffer, symmetriccipher};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};

const KEY: &[u8; 32] = &[116, 38, 133, 187, 110, 252, 192, 223, 94, 84, 199, 246, 30, 209, 207, 179, 29, 168, 160, 150, 5, 219, 39, 171, 51, 69, 20, 212, 222, 116, 58, 50];
const IV: &[u8; 16] = &[112, 186, 204, 222, 128, 139, 194, 48, 39, 55, 218, 65, 207, 118, 3, 93];
const KEY_SHUFFLE: &[u8; 32] = &[4, 171, 33, 13, 16, 160, 191, 143, 22, 20, 78, 185, 59, 189, 98, 202, 39, 188, 177, 56, 169, 99, 154, 72, 12, 82, 117, 165, 247, 115, 126, 102];

fn main() {
    let input_filename = env::args().nth(1).expect("Usage: Must supply a filename to the program.");

    let data = match get_file_data(input_filename.as_ref()) {
        Ok(data) => data,
        Err(reason) => panic!("Failed to extract file data because: {}", reason),
    };

    let crypted = encrypt(data.as_ref(), KEY, IV).unwrap();

    create_new_file(input_filename.as_ref(), crypted).unwrap();
}

fn get_real_key() -> [u8; 32] {
    let mut real_key: [u8; 32] = [0; 32];
    for (i, elem) in KEY_SHUFFLE.iter().enumerate() {
        let real_index = elem % 32;
        real_key[i] = KEY[real_index as usize];
    }
    real_key
}

fn get_file_data(filename: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(filename);
    let mut file = File::open(path).unwrap();
    let mut data = Vec::<u8>::new();
    file.read_to_end(&mut data).unwrap();
    Ok(data)
}

fn create_new_file(filename: &str, data: Vec<u8>) -> Result<(), String> {
    let mut new_filename = String::from(filename);
    new_filename.push_str(".ct");
    let mut file = File::create(new_filename).unwrap();
    file.write(data.as_ref()).unwrap();
    Ok(())
}

fn encrypt(
    data: &[u8],
    _key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, &get_real_key(), iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut out_buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut out_buffer);

    loop {
        let result = encryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        if let BufferResult::BufferUnderflow = result {
            break;
        }
    }

    Ok(final_result)
}
