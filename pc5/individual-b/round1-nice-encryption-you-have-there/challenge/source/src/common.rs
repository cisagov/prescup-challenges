
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use std::error::Error;
use std::fmt::Display;
use std::ops::BitXor;

use openssl::aes::{aes_ige, AesKey};
use openssl::symm::Mode;

const KEY_A: [u8; 16] = [obfstr::random!(u8); 16];
const KEY_B: [u8; 16] = [obfstr::random!(u8); 16];
const KEY_C: [u8; 16] = [obfstr::random!(u8); 16];

// IVs are supposed to change, but it doesn't really matter for this challenge.
const ORIGINAL_IV_A: [u8; 32] = [obfstr::random!(u8); 32];
const ORIGINAL_IV_B: [u8; 32] = [obfstr::random!(u8); 32];
const ORIGINAL_IV_C: [u8; 32] = [obfstr::random!(u8); 32];

pub const PORT: u16 = 23456;

const AES_BLOCK_SIZE: usize = 16;

#[derive(Debug)]
struct DataAlreadyPaddedError;
impl Display for DataAlreadyPaddedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Given plaintext was already padded.")
    }
}
impl Error for DataAlreadyPaddedError {}

#[derive(Debug)]
struct DataNotPaddedError;
impl Display for DataNotPaddedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Decrypted ciphertext was not padded.")
    }
}
impl Error for DataNotPaddedError {}

fn xor_triple<T: BitXor<Output = T> + Copy>(a: &[T], b: &[T], c: &[T]) -> Vec<T> {
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| x ^ y)
        .zip(c.iter())
        .map(|(y, &z)| y ^ z)
        .collect()
}

fn is_pkcs7_padded(input: &Vec<u8>) -> bool {
    if input.len() < AES_BLOCK_SIZE {
        return false;
    }

    let padding_len = *input.last().unwrap();
    if padding_len > AES_BLOCK_SIZE as u8 {
        return false;
    }

    let padding_buf = [padding_len; AES_BLOCK_SIZE];
    if !input.ends_with(&padding_buf[..padding_len as usize]) {
        return false;
    }

    true
}

fn aes_pkcs7_pad(input: &mut Vec<u8>) -> Result<(), DataAlreadyPaddedError> {
    if is_pkcs7_padded(input) {
        return Err(DataAlreadyPaddedError);
    }

    let padding_len = AES_BLOCK_SIZE - input.len() % AES_BLOCK_SIZE;
    input.resize(input.len() + padding_len, padding_len as u8);

    Ok(())
}

fn aes_pkcs7_depad(input: &mut Vec<u8>) -> Result<(), DataNotPaddedError> {
    if !is_pkcs7_padded(input) {
        return Err(DataNotPaddedError);
    }

    let padding_len = *input.last().unwrap();
    input.resize(input.len() - padding_len as usize, 0);

    Ok(())
}

pub fn aes(input: &[u8], mode: Mode) -> Result<Vec<u8>, Box<dyn Error>> {
    let combined_key = xor_triple(&KEY_A, &KEY_B, &KEY_C);

    let key = match mode {
        Mode::Encrypt => AesKey::new_encrypt(&combined_key).unwrap(),
        Mode::Decrypt => AesKey::new_decrypt(&combined_key).unwrap(),
    };

    let mut iv = xor_triple(&ORIGINAL_IV_A, &ORIGINAL_IV_B, &ORIGINAL_IV_C);

    let mut input = input.to_vec();
    if let Mode::Encrypt = mode {
        aes_pkcs7_pad(&mut input)?;
    }

    let mut output = vec![0; input.len()];

    aes_ige(&input, &mut output, &key, &mut iv, mode);

    if let Mode::Decrypt = mode {
        aes_pkcs7_depad(&mut output)?;
    }

    Ok(output)
}

