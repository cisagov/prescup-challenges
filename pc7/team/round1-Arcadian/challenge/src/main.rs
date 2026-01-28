// src/main.rs

use libc::{ptrace, PTRACE_TRACEME};
use std::{
    env,
    arch::asm,               // inline‐asm
    io::{self, Write},
    process::exit,
    thread,
    time::Duration
};


// ① Pull in compile-time-generated ciphertext & key constants
include!(concat!(env!("OUT_DIR"), "/tokens.rs"));

/// XOR+shift decrypt: plaintext[i] = cipher[i] ^ (key + i)
fn decrypt(cipher: &[u8], key: u8) -> String {
    cipher
        .iter()
        .enumerate()
        .map(|(i, &b)| (b ^ key.wrapping_add(i as u8)) as char)
        .collect()
}

fn main() {
    let stage = parse_stage().unwrap_or(0);
    match stage {
        0 => run_all(),
        1 => stage1(),
        2 => stage2(),
        3 => stage3(),
        4 => stage4(),
        5 => stage5(),
        n => {
            eprintln!("Invalid stage: {}. Must be 1–5.", n);
            exit(1);
        }
    }
}

fn parse_stage() -> Option<u8> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(val) = arg.strip_prefix("--stage=") {
            return val.parse().ok();
        }
        if arg == "--stage" {
            if let Some(val) = args.next() {
                return val.parse().ok();
            }
        }
    }
    None
}

fn run_all() {
    println!("Welcome to Arcadian... Let's begin the hunt.");
    stage1();
    stage2();
    stage3();
    stage4();
    stage5();
}

fn stage1() {
    println!("\n[Stage 1] 🪓 Split String Fragmentation");
    let correct = ["T0K", "3N1", "PC7", "RUS", "TIC"];
    print!("Submission Example: SEE DOG RUN C DOS\n");
    print!("Enter the {} fragments (use spaces between them): > ", correct.len());
    io::stdout().flush().unwrap();

    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    if buf.trim().split_whitespace().ne(correct.iter().copied()) {
        eprintln!("Wrong sequence. Exiting.");
        exit(1);
    }

    let token1 = decrypt(TOKEN1_CIPHER, TOKEN1_KEY);
    println!("✅ TOKEN1: {}", token1);
}

fn stage2() {
    println!("\n[Stage 2] 🌽 Function Pointer Maze");
    type MazeFn = fn();

    // 1) Named indices
    const L: usize = 0;
    const R: usize = 1;
    const U: usize = 2;
    const D: usize = 3;
    const X: usize = 4;
    const B: usize = 5;

    // 2) Table of function pointers, length = 6
    let table: [MazeFn; 6] =
        [mf_left, mf_right, mf_up, mf_down, mf_diagonal, mf_back];

    // 3) The “correct” path through that table
    let path: [usize; 6] = [L, R, U, D, L, X];

    println!("\nObjective: Leave the maze to get the token \
              (Possible moves: L R U D X B)");
    println!("Legend: L=Left, R=Right, U=Up, D=Down, X=Diagonal, B=Back");
    println!("Example: L D D X U B");
    print!("\nEnter your {} moves: > ", path.len());
    io::stdout().flush().unwrap();

    // 4) Read user input as *strings* and map to indices
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    let parts: Vec<usize> = buf
        .trim()
        .split_whitespace()
        .map(|s| match s {
            "L" => L,
            "R" => R,
            "U" => U,
            "D" => D,
            "X" => X,
            "B" => B,
            _   => { eprintln!("Invalid move: {}", s); exit(1) }
        })
        .collect();

    if parts != path {
        eprintln!("Wrong maze. Exiting.");
        exit(1);
    }

    // 5) Walk the maze
    for &idx in &path {
        table[idx]();
    }

    let token2 = decrypt(TOKEN2_CIPHER, TOKEN2_KEY);
    println!("✅ TOKEN2: {}", token2);
}

// ────────────────────────────────────────────────────────────────────

fn mf_left()     { println!("→ Move: Left"); }
fn mf_right()    { println!("→ Move: Right"); }
fn mf_up()       { println!("→ Move: Up"); }
fn mf_down()     { println!("→ Move: Down"); }
fn mf_diagonal() { println!("→ Move: Diagonal"); }
fn mf_back()     { println!("→ Move: Backwards"); }

/// Stage 3: 🔄 Self-Modifying Memory
///
/// This routine will decrypt TOKEN3 in-place and then exit,
/// forcing you to attach a debugger or dump memory *after* the decryption.
fn stage3() {
    println!("\n[Stage 3] 🔄 Self-Modifying Memory");
    println!("Decrypting TOKEN3 in 5 seconds…");
    thread::sleep(Duration::from_secs(5));

    // ── In-place XOR+shift decryption of the static cipher array ──
    unsafe {
        let ptr = TOKEN3_CIPHER.as_ptr() as *mut u8;
        for i in 0..TOKEN3_CIPHER.len() {
            let key = TOKEN3_KEY.wrapping_add(i as u8);
            let c = ptr.add(i).read();
            ptr.add(i).write(c ^ key);
        }
    }

    // ── Force a SIGTRAP so debuggers will always stop right here ──
    unsafe { libc::raise(libc::SIGTRAP) };

    // ── Interactive reveal prompt ──
    println!("Decryption complete!");
    println!("Type `dump` to reveal TOKEN3:");
    print!("> "); io::stdout().flush().unwrap();

    let mut cmd = String::new();
    io::stdin().read_line(&mut cmd).unwrap();
    if cmd.trim() == "dump" {
        let token3 = decrypt(TOKEN3_CIPHER, TOKEN3_KEY);
        println!("✅ TOKEN3: {}", token3);
    } else {
        eprintln!("Unknown command. Exiting.");
    }

    exit(0);
}


/// A writable flag in .data (initially 0).  
/// Patch this byte to `1` (or NOP out the `int3`) to unlock TOKEN4.
#[no_mangle]
static mut STAGE4_UNLOCK: u8 = 0;

/// A one‐byte flag in .data, initially 1 (“locked”).
/// After patching this to 0 via a binary patch,
/// execution will fall through and reveal TOKEN4.
#[no_mangle]
static mut STAGE4_LOCK: u8 = 1;

fn stage4() {
    println!("\n[Stage 4] 🛡️ Anti-RE Protections");

    // ① Anti‐debug check
    let res = unsafe { ptrace(PTRACE_TRACEME, 0, 0, 0) };
    if res == -1 {
        eprintln!("❌ Debugger detected! Exiting.");
        exit(1);
    }

    // ② If still locked (==1), clean exit before reveal
    println!("✅ Service OK. No issues detected.");
    unsafe {
        if STAGE4_LOCK == 1 {
            exit(0);
        }
    }

    // ③ Only when STAGE4_LOCK == 0 does execution reach here:
    println!("🥷 Bypass detected! Revealing TOKEN4…");
    print!("Press ENTER to continue: ");
    io::stdout().flush().unwrap();
    let mut dummy = String::new();
    io::stdin().read_line(&mut dummy).unwrap();

    let token4 = decrypt(TOKEN4_CIPHER, TOKEN4_KEY);
    println!("✅ TOKEN4: {}", token4);
}

fn stage5() {
    println!("\n[Stage 5] 🕵️ Custom XOR-Shift Encryption");
    print!("Ciphertext: ");
    for &b in TOKEN5_CIPHER {
        print!("0x{:02X} ", b);
    }
    println!("\nBase key is: 0x{:02X}", TOKEN5_KEY);

    print!("🚀 Enter the decrypted final token: > ");
    io::stdout().flush().unwrap();
    let mut guess = String::new();
    io::stdin().read_line(&mut guess).unwrap();
    let expected = decrypt(TOKEN5_CIPHER, TOKEN5_KEY);

    if guess.trim() != expected {
        eprintln!("Wrong final token. Exiting.");
        exit(1);
    }
    println!("✅ TOKEN5: {}", expected);
    println!("\n🎉 Mission complete!");
}