/*
 * Copyright 2025 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
 *
 * This Software includes and/or makes use of Third-Party Software each subject to its own license.
 * DM25-0166 */

use std::error::Error;
use std::fmt::Display;
use std::io::{Read, Write};
use std::panic;

use aes_gcm::aead::{Aead, AeadCore, Key, KeyInit, Nonce, OsRng};
use aes_gcm::{Aes256Gcm, Error as AesGcmError};
use base64::{prelude::BASE64_STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

mod errors;
pub(crate) use errors::*;

pub(crate) const PORT: u16 = 23456;

pub(crate) type KeyBytes = [u8; 32];

pub(crate) struct KeyPair {
    pub(crate) public: PublicKey,
    pub(crate) private: StaticSecret,
}
impl KeyPair {
    pub(crate) fn new() -> Self {
        let private = StaticSecret::random();

        Self::from_key_bytes(private.as_bytes())
    }

    pub(crate) fn from_key_bytes(key_bytes: &KeyBytes) -> Self {
        let private = StaticSecret::from(*key_bytes);

        KeyPair {
            public: PublicKey::from(&private),
            private,
        }
    }
}
impl Display for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let disp_str = format!(
            "KeyPair {{\n\tpublic:  {:?}\n\tprivate: {:?}\n}}",
            BASE64_STANDARD.encode(self.public.to_bytes()),
            BASE64_STANDARD.encode(self.private.to_bytes())
        );
        f.write_str(disp_str.as_str())
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub(crate) struct Message {
    nonce: Option<[u8; 12]>,
    data: Vec<u8>,
}
impl Message {
    pub(crate) fn new(data: &[u8]) -> Self {
        Self {
            nonce: None,
            data: data.to_vec(),
        }
    }

    pub(crate) fn enc(self, shared_secret: &SharedSecret) -> Result<Self, AesGcmError> {
        let fresh_nonce = match self.nonce {
            None => Aes256Gcm::generate_nonce(OsRng),
            Some(_) => return Err(AesGcmError),
        };
        let nonce = Some(fresh_nonce.into());

        let derived_key = Self::derive_key(shared_secret);

        let cipher = Aes256Gcm::new(&derived_key);
        let data = cipher.encrypt(&fresh_nonce, self.data.as_slice())?.to_vec();

        Ok(Self { nonce, data })
    }

    pub(crate) fn dec(self, shared_secret: &SharedSecret) -> Result<Self, AesGcmError> {
        let nonce: Nonce<Aes256Gcm> = match self.nonce {
            None => return Err(AesGcmError),
            Some(n) => n.into(),
        };

        let derived_key = Self::derive_key(shared_secret);

        let cipher = Aes256Gcm::new(&derived_key);
        Ok(Self {
            data: cipher.decrypt(&nonce, self.data.as_slice())?,
            nonce: None,
        })
    }

    fn derive_key(shared_secret: &SharedSecret) -> Key<Aes256Gcm> {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.to_bytes());
        hasher.finalize()
    }
}

pub(crate) fn read_message<R: Read>(reader: &mut R) -> Result<Message, MessageDeserializeError> {
    use MessageDeserializeErrorType::*;

    let mut len_buf = [0; 8];
    if let Err(e) = reader.read_exact(&mut len_buf) {
        return Err(MessageDeserializeError::new(ReadLength, Box::new(e)));
    }

    let read_len = u64::from_be_bytes(len_buf);
    if read_len == 0 {
        return Err(MessageDeserializeError::new_msg(
            ZeroLength,
            "Read length equal to 0.",
        ));
    }

    let mut msg_buf = match panic::catch_unwind(|| vec![0; read_len as usize]) {
        Ok(b) => b,
        Err(_) => {
            return Err(MessageDeserializeError::new_msg(
                VeryLargeLength,
                "capacity overflow",
            ))
        }
    };

    if let Err(e) = reader.read_exact(&mut msg_buf) {
        return Err(MessageDeserializeError::new(ReadMessageBytes, Box::new(e)));
    }

    let message: Message = match serde_json::from_slice(&msg_buf) {
        Ok(m) => m,
        Err(e) => return Err(MessageDeserializeError::new(FromSlice, Box::new(e))),
    };

    Ok(message)
}

pub(crate) fn write_message<W: Write>(
    writer: &mut W,
    message: &Message,
) -> Result<(), MessageSerializeError> {
    use MessageSerializeErrorType::*;

    let serialized = match serde_json::to_vec(&message) {
        Ok(v) => v,
        Err(e) => return Err(MessageSerializeError::new(ToVec, Box::new(e))),
    };

    if let Err(e) = writer.write(&(serialized.len() as u64).to_be_bytes()) {
        return Err(MessageSerializeError::new(WriteLength, Box::new(e)));
    };

    if let Err(e) = writer.write(&serialized) {
        return Err(MessageSerializeError::new(WriteMessage, Box::new(e)));
    };

    if let Err(e) = writer.flush() {
        return Err(MessageSerializeError::new(Flush, Box::new(e)));
    }

    Ok(())
}

pub(crate) fn negotiate_shared_secret<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key_pair: &KeyPair,
) -> Result<SharedSecret, Box<dyn Error>> {
    let our_pub_key = Message::new(key_pair.public.as_bytes());
    write_message(writer, &our_pub_key)?;
    let their_pub_key = read_message(reader)?;

    if their_pub_key.data.len() != 32 {
        return Err(Box::new(NegotiationError::new(
            NegotiationErrorType::TheirPubKeyLength,
        )));
    }
    let mut key_bytes = [0; 32];
    for (i, &byte) in their_pub_key.data.iter().enumerate() {
        key_bytes[i] = byte;
    }

    Ok(key_pair.private.diffie_hellman(&key_bytes.into()))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn shared_secret() {
        let keypair_a = KeyPair::new();
        let keypair_b = KeyPair::new();

        let shared_a = keypair_a.private.diffie_hellman(&keypair_b.public);
        let shared_b = keypair_b.private.diffie_hellman(&keypair_a.public);

        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }

    #[test]
    fn repeatable_secret() {
        let keypair_a = KeyPair::from_key_bytes(&[50; 32]);
        let keypair_b = KeyPair::from_key_bytes(&[80; 32]);

        let shared_a = keypair_a.private.diffie_hellman(&keypair_b.public);
        let shared_b = keypair_b.private.diffie_hellman(&keypair_a.public);

        let keypair_c = KeyPair::from_key_bytes(&[50; 32]);
        let keypair_d = KeyPair::from_key_bytes(&[80; 32]);

        let shared_c = keypair_c.private.diffie_hellman(&keypair_d.public);
        let shared_d = keypair_d.private.diffie_hellman(&keypair_c.public);

        assert_eq!(shared_a.as_bytes(), shared_c.as_bytes());
        assert_eq!(shared_b.as_bytes(), shared_d.as_bytes());
    }

    #[test]
    fn enc_dec() {
        let key = Aes256Gcm::generate_key(OsRng);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let input_plaintext = b"plaintext".as_ref();
        let ciphertext = cipher.encrypt(&nonce, input_plaintext).unwrap();
        let output_plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

        assert_eq!(&input_plaintext, &output_plaintext);
    }

    #[test]
    fn serialize_message() {
        let message = Message {
            nonce: None,
            data: b"this is a test".to_vec(),
        };

        let serialized = serde_json::to_vec(&message).unwrap();
        println!("{}", String::from_utf8_lossy(&serialized));
        let deserialized: Message = serde_json::from_slice(serialized.as_slice()).unwrap();

        assert_eq!(message, deserialized);
    }

    #[test]
    fn write_read() {
        let mut cursor = Cursor::new(vec![]);
        let out_message = Message {
            nonce: None,
            data: b"test message".to_vec(),
        };
        write_message(&mut cursor, &out_message).unwrap();

        cursor.set_position(0);
        let in_message = read_message(&mut cursor).unwrap();

        assert_eq!(out_message, in_message);
    }

    #[test]
    fn read_large_len() {
        let mut cursor = Cursor::new(vec![]);
        let out_message = Message {
            nonce: None,
            data: b"test message".to_vec(),
        };

        // Redo the steps for write_message but with a max int.
        let serialized = serde_json::to_vec(&out_message).unwrap();
        cursor.write(&(u64::MAX).to_be_bytes()).unwrap();
        cursor.write(&serialized).unwrap();

        cursor.set_position(0);
        if let Err(MessageDeserializeError {
            error_type: MessageDeserializeErrorType::VeryLargeLength,
            ..
        }) = read_message(&mut cursor)
        {
        } else {
            panic!("Expected a VeryLargeLength error.");
        }
    }

    #[test]
    fn message_enc_dec() {
        let keypair_a = KeyPair::from_key_bytes(&[50; 32]);
        let keypair_b = KeyPair::from_key_bytes(&[80; 32]);
        let shared_secret = keypair_a.private.diffie_hellman(&keypair_b.public);

        let data = b"hello";
        let msg = Message::new(data);

        let enc_msg = msg.enc(&shared_secret).unwrap();
        let dec_msg = enc_msg.dec(&shared_secret).unwrap();

        assert_eq!(data.to_vec(), dec_msg.data);
    }
}
