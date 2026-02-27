use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use base64::{engine::general_purpose, Engine as _};
use crc32fast::Hasher;

const MAGIC: &[u8;4] = b"RPLY";

#[repr(C)]
struct ParseFrame {
    buf: [u8; 64],
    redact: u8,
    _pad: [u8; 7],
}

fn read_exact(stream: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn u16_le(b: &[u8]) -> u16 { u16::from_le_bytes([b[0], b[1]]) }
fn u32_le(b: &[u8]) -> u32 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }

fn handle_client(mut stream: TcpStream, ghost_secret: Vec<u8>) -> std::io::Result<()> {
    // Simple length-prefixed protocol: 4 bytes little-endian length, then frame bytes.
    let len_b = read_exact(&mut stream, 4)?;
    let n = u32_le(&len_b) as usize;
    if n > 8192 {
        stream.write_all(b"ERR too_big")?;
        return Ok(());
    }
    let frame = read_exact(&mut stream, n)?;

    // Validate basic structure
    if frame.len() < 4 + 1 + 1 + 2 + 4 {
        stream.write_all(b"ERR short")?;
        return Ok(());
    }
    if &frame[0..4] != MAGIC {
        stream.write_all(b"ERR magic")?;
        return Ok(());
    }
    let _ver = frame[4];
    let _flags = frame[5];
    let payload_len = u16_le(&frame[6..8]) as usize;
    let header_len = 8;
    if frame.len() != header_len + payload_len + 4 {
        stream.write_all(b"ERR len")?;
        return Ok(());
    }
    let payload = &frame[8..8+payload_len];
    let crc_recv = u32_le(&frame[8+payload_len..8+payload_len+4]);

    // CRC32 over header+payload (excluding trailing crc field)
    let mut hasher = Hasher::new();
    hasher.update(&frame[0..8+payload_len]);
    let crc_calc = hasher.finalize();
    if crc_calc != crc_recv {
        stream.write_all(b"ERR crc")?;
        return Ok(());
    }

    // Parse payload: cmd byte then cmd data
    if payload.is_empty() {
        stream.write_all(b"ERR payload")?;
        return Ok(());
    }
    let cmd = payload[0];

    // Vulnerable parse path for STAT command:
    // We intentionally copy payload bytes into a fixed-size stack buffer without bounds checks.
    // The "redact" byte is adjacent; an overflow can flip it to 0.
    if cmd == b'S' {
        let mut pf = ParseFrame { buf: [0u8;64], redact: 1, _pad: [0u8;7] };

        // Vulnerability: we cap the copy to keep the daemon stable, but still allow a
        // one-byte overwrite of `redact` (the 65th cmd_data byte).
        // Off-by-one style bug: we intended to copy at most 64 bytes of cmd data
        // into pf.buf, but the `redact` byte sits adjacent in the struct and our
        // length calculation allows writing one extra byte.
        let copy_len = std::cmp::min(payload_len.saturating_sub(1), 65);
        unsafe {
            let src = payload.as_ptr().add(1);
            let dst = (&mut pf as *mut ParseFrame) as *mut u8; // start at buf[0]
            std::ptr::copy_nonoverlapping(src, dst, copy_len);
        }

        // Response is base64 of secret, but redacted unless pf.redact == 0
        if pf.redact == 0 {
            let b64 = general_purpose::STANDARD.encode(&ghost_secret);
            stream.write_all(b"OK ")?;
            stream.write_all(b64.as_bytes())?;
            return Ok(());
        } else {
            // Redacted response looks plausible but useless.
            let mut fake = vec![0u8; ghost_secret.len()];
            for (i, b) in fake.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(13).wrapping_add(7);
            }
            let b64 = general_purpose::STANDARD.encode(&fake);
            stream.write_all(b"OK ")?;
            stream.write_all(b64.as_bytes())?;
            return Ok(());
        }
    }

    stream.write_all(b"ERR cmd")?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    // Args:
    // 1) bind addr, e.g. 127.0.0.1:9093
    // 2) ghost_secret_b64
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: replayd 127.0.0.1:9093 <ghost_secret_b64>");
        std::process::exit(2);
    }
    let bind = &args[1];
    let secret_b64 = &args[2];
    let ghost_secret = general_purpose::STANDARD.decode(secret_b64).unwrap_or_else(|_| vec![0u8;32]);

    let listener = TcpListener::bind(bind)?;
    eprintln!("replayd listening on {}", bind);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let gs = ghost_secret.clone();
                thread::spawn(move || {
                    let _ = handle_client(s, gs);
                });
            }
            Err(e) => {
                eprintln!("accept error: {}", e);
            }
        }
    }
    Ok(())
}
