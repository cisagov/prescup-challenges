
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use std::{
    error::Error,
    fmt::Display,
    io::{Error as IoError, ErrorKind, Read, Write},
};

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes128Gcm, Key, KeyInit,
};
use anyhow::Result as AnyhowResult;
use generic_array::GenericArray;
use obfstr::obfstr;
use rand::Rng;
use strum::{Display, EnumString};

const KEY: &[u8; 16] = b"hello this is 16";

pub(crate) const LOGIN_SUCCESS: &str = "Login Successful";
pub(crate) const LOGIN_FAILURE: &str = "Login Failed";

#[inline]
pub(crate) fn get_username() -> &'static str {
    "chris_p_bacon"
}

#[inline]
pub(crate) fn get_password() -> String {
    String::from(obfstr!(include_str!("token1")).trim())
}

pub const PORT: u16 = 23456;

fn random_choice<T>(a: &[T]) -> &T {
    let index = rand::thread_rng().gen_range(0..a.len());

    &a[index]
}

#[derive(Debug)]
struct MessageLengthError {}
impl Display for MessageLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Received message length of 0.")
    }
}
impl Error for MessageLengthError {}

/// in_string will be cleared and then trimmed.
pub(crate) fn read_message<R: Read>(reader: &mut R, in_string: &mut String) -> AnyhowResult<()> {
    let mut length_buf = [0u8; 4];
    reader.read_exact(&mut length_buf)?;
    let message_length = u32::from_be_bytes(length_buf);

    if message_length == 0 {
        return Err(MessageLengthError {}.into());
    }

    let mut nonce = [0u8; 12];
    reader.read_exact(&mut nonce)?;
    let mut message_buf = vec![0u8; message_length as usize];
    reader.read_exact(&mut message_buf)?;

    let message_bytes = aes(&mut nonce, &message_buf, Mode::Decrypt)?;
    let message = String::from_utf8(message_bytes)?;
    in_string.clear();
    in_string.push_str(&message);
    in_string.truncate(in_string.trim_end().len());

    Ok(())
}

pub(crate) fn read_message_timeout_ok<R: Read>(
    reader: &mut R,
    in_string: &mut String,
) -> AnyhowResult<()> {
    if let Err(e) = read_message(reader, in_string) {
        return match e.downcast_ref::<IoError>() {
            Some(error) => match error.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => Ok(()),
                _ => Err(e),
            },
            None => Err(e),
        };
    };

    Ok(())
}

pub(crate) fn write_message<W: Write>(writer: &mut W, out_string: &str) -> AnyhowResult<()> {
    let mut nonce = [0u8; 12];
    let encrypted_message = aes(&mut nonce, out_string.as_bytes(), Mode::Encrypt)?;

    let message_length = (encrypted_message.len() as u32).to_be_bytes();

    writer.write(&message_length)?;
    writer.write(&nonce)?;
    writer.write(&encrypted_message)?;
    writer.flush()?;

    Ok(())
}

#[derive(Debug)]
pub(crate) struct LoginError {}
impl Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", LOGIN_FAILURE)
    }
}
impl Error for LoginError {}

#[derive(Debug)]
struct EncryptionError {
    msg: String,
}
impl Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}
impl Error for EncryptionError {}

pub(crate) enum Mode {
    Encrypt,
    Decrypt,
}

type NonceBytes = [u8; 12];
/// If mode == Mode::Encrypt, nonce is an output buffer.
/// If mode == Mode::Decrypt, nonce is an input buffer.
pub(crate) fn aes(nonce_bytes: &mut NonceBytes, input: &[u8], mode: Mode) -> AnyhowResult<Vec<u8>> {
    let key = Key::<Aes128Gcm>::from_slice(KEY);
    let cipher = Aes128Gcm::new(&key);

    if let Mode::Encrypt = mode {
        let nonce: NonceBytes = Aes128Gcm::generate_nonce(&mut OsRng).into();
        for (i, byte) in nonce.iter().enumerate() {
            nonce_bytes[i] = *byte;
        }
    }

    let nonce = GenericArray::clone_from_slice(nonce_bytes);
    let output = match mode {
        Mode::Encrypt => cipher.encrypt(&nonce, input),
        Mode::Decrypt => cipher.decrypt(&nonce, input),
    };

    match output {
        Ok(o) => Ok(o),
        Err(e) => Err(EncryptionError { msg: e.to_string() }.into()),
    }
}

#[derive(Debug, Display, Clone, Copy, EnumString)]
pub(crate) enum Operation {
    #[strum(serialize = "+")]
    Add,
    #[strum(serialize = "-")]
    Subtract,
    #[strum(serialize = "*")]
    Multiply,
    #[strum(serialize = "/")]
    Divide,
}

impl Operation {
    pub(crate) fn random() -> Self {
        let variants = [Self::Add, Self::Subtract, Self::Multiply, Self::Divide];

        *random_choice(&variants)
    }

    fn generate_single_operand() -> i32 {
        rand::thread_rng().gen_range(-1000..=1000)
    }

    pub(crate) fn generate_operands(&self) -> (i32, i32) {
        if let Self::Divide = self {
            // Ensure that all quotients are integers to avoid rounding issues.
            let mut divisor;
            loop {
                divisor = Self::generate_single_operand();
                if divisor != 0 {
                    break;
                }
            }

            let dividend_factor = Self::generate_single_operand();

            (dividend_factor * divisor, divisor)
        } else {
            (
                Self::generate_single_operand(),
                Self::generate_single_operand(),
            )
        }
    }

    pub(crate) fn perform_operation(&self, op_1: i32, op_2: i32) -> i32 {
        match self {
            Self::Add => op_1 + op_2,
            Self::Subtract => op_1 - op_2,
            Self::Multiply => op_1 * op_2,
            Self::Divide => op_1 / op_2,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{aes, read_message, write_message};

    #[test]
    fn test_encryption() {
        let message = "Hello.";
        let mut nonce_bytes = [0; 12];
        let ciphertext = aes(&mut nonce_bytes, message.as_bytes(), super::Mode::Encrypt).unwrap();
        let plaintext = aes(&mut nonce_bytes, &ciphertext, super::Mode::Decrypt).unwrap();

        assert_eq!(&String::from_utf8(plaintext).unwrap(), message);
    }

    #[test]
    fn test_read_write_message() {
        let mut cursor = Cursor::new(vec![]);
        let message = "test message";
        write_message(&mut cursor, message).unwrap();

        cursor.set_position(0);
        let mut in_string = String::new();
        read_message(&mut cursor, &mut in_string).unwrap();

        assert_eq!(message, in_string);
    }
}

