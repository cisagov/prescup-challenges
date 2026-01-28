// build.rs

use std::{env, fs::File, io::Write, path::Path};

fn main() {
    // Re-run whenever any TOKENn env changes:
    for tok in &["TOKEN1","TOKEN2","TOKEN3","TOKEN4","TOKEN5"] {
        println!("cargo:rerun-if-env-changed={}", tok);
    }

    // Our simple cipher: base key, then +i for each byte
    const BASE_KEY: u8 = 0xA5;
    let tokens = ["TOKEN1","TOKEN2","TOKEN3","TOKEN4","TOKEN5"];

    let mut out = String::new();
    for &tok in &tokens {
        // Read the plaintext from the build-time env:
        let plain = env::var(tok)
            .unwrap_or_else(|_| panic!("build.rs: missing env var {}", tok));

        // Encrypt: cipher[i] = plain_bytes[i] ^ (BASE_KEY + i)
        let cipher: Vec<u8> = plain
            .bytes()
            .enumerate()
            .map(|(i, b)| b ^ BASE_KEY.wrapping_add(i as u8))
            .collect();

        // Emit Rust constants:
        out.push_str(&format!(
            "pub const {0}_CIPHER: &[u8] = &{1:?};\n",
            tok, cipher
        ));
        out.push_str(&format!(
            "pub const {0}_KEY: u8 = 0x{1:02X};\n\n",
            tok, BASE_KEY
        ));
    }

    // Write to $OUT_DIR/tokens.rs
    let dst = Path::new(&env::var("OUT_DIR").unwrap()).join("tokens.rs");
    let mut f = File::create(dst).unwrap();
    f.write_all(out.as_bytes()).unwrap();
}
