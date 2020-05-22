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

#![feature(proc_macro_hygiene, decl_macro)]
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate crypto;
extern crate rmp_serde;

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};

use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer, symmetriccipher};

use std::process::exit;

mod opcodes;

const KEY: [u8; 32] = [
    214, 139, 213, 105, 202, 32, 18, 140, 140, 64, 137, 199, 28, 226, 26, 158, 56, 12, 122, 222,
    82, 193, 229, 134, 139, 170, 211, 15, 31, 10, 179, 143,
];
const IV: [u8; 16] = [
    201, 34, 100, 65, 130, 153, 15, 42, 220, 38, 86, 152, 56, 215, 186, 107,
];
// Originally 10.10.10.60:8000 during President's Cup.
const DEFAULT_SERVER: &str = "localhost:8000";

#[derive(Clone, Debug, Deserialize)]
struct GameState {
    money: u64,

    bodyguard_amt: u64,
    staple_goods_amt: u64,
    luxury_goods_amt: u64,
    weapons_amt: u64,
    armor_amt: u64,

    bodyguard_id: u8,
    staple_goods_id: u8,
    luxury_goods_id: u8,
    weapons_id: u8,
    armor_id: u8,

    bodyguard_buy_price: u64,
    staple_goods_buy_price: u64,
    luxury_goods_buy_price: u64,
    weapons_buy_price: u64,
    armor_buy_price: u64,

    staple_goods_sell_price: u64,
    luxury_goods_sell_price: u64,
    weapons_sell_price: u64,
    armor_sell_price: u64,
}

impl GameState {
    fn display(&self) {
        println!();
        println!("###############################################################################");
        println!("Inventory:");
        println!("\tMoney: {}", self.money);
        println!("\tBodyguards: {}", self.bodyguard_amt);
        println!("\tCurrent staple goods: {}", self.staple_goods_amt);
        println!("\tCurrent luxury goods: {}", self.luxury_goods_amt);
        println!("\tCurrent weapons: {}", self.weapons_amt);
        println!("\tCurrent armor: {}", self.armor_amt);
        println!();
        println!("Prices in this town:");
        println!("\tBodyguards | ID: {} | Hire: {}", self.bodyguard_id, self.bodyguard_buy_price);
        println!(
            "\tStaple Goods | ID: {} | Buy: {} | Sell: {}",
            self.staple_goods_id, self.staple_goods_buy_price, self.staple_goods_sell_price
        );
        println!(
            "\tLuxury Goods | ID: {} | Buy: {} | Sell: {}",
            self.luxury_goods_id, self.luxury_goods_buy_price, self.luxury_goods_sell_price
        );
        println!(
            "\tWeapons | ID: {} | Buy: {} | Sell: {}",
            self.weapons_id, self.weapons_buy_price, self.weapons_sell_price
        );
        println!(
            "\tArmor | ID: {} | Buy: {} | Sell: {}",
            self.armor_id, self.armor_buy_price, self.armor_sell_price
        );
        println!("###############################################################################");
        println!();
    }
}

fn send_and_receive_sync(buf: Vec<u8>) -> Vec<u8> {
    match TcpStream::connect(DEFAULT_SERVER) {
        Ok(mut stream) => {
            let out_ciphertext = match encrypt(&buf, &KEY, &IV) {
                Ok(ct) => ct,
                Err(_) => {
                    println!("Failed to encrypt outgoing message. This error should be reported.");
                    stream.shutdown(Shutdown::Both).unwrap();
                    exit(-1);
                }
            };
            stream.write(&out_ciphertext).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();

            let mut received = Vec::new();
            stream.read_to_end(&mut received).unwrap();
            stream.shutdown(Shutdown::Read).unwrap();
            match decrypt(&received, &KEY, &IV) {
                Ok(pt) => return pt,
                Err(_) => {
                    println!("Failed to decrypt incoming message. This error should be reported.");
                    exit(-1);
                }
            };
        }
        Err(e) => {
            println!(
                "Failed to connect to server, this is an error and should be reported: {}",
                e
            );
            exit(-1);
        }
    }
}

fn request_state() -> GameState {
    let out_buf = vec![{ opcodes::QUERY_STATE_OPCODE }];

    let in_buf = send_and_receive_sync(out_buf);
    rmp_serde::from_slice(&in_buf).expect(
        "Did not receive expected game state from the server. This error should be reported.",
    )
}

fn request_goods() -> GameState {
    let out_buf = vec![{ opcodes::LIST_GOODS_OPCODE }];

    let in_buf = send_and_receive_sync(out_buf);
    rmp_serde::from_slice(&in_buf).expect(
        "Did not receive expected game state from the server. This error should be reported.",
    )
}

fn reset_game() {
    let out_buf = vec![{ opcodes::RESET_OPCODE }];

    let in_buf = send_and_receive_sync(out_buf);
    let response: String = rmp_serde::from_slice(&in_buf).expect(
        "Did not receive expected response from the server. This error should be reported.",
    );
    println!("{}", response);
}

fn travel() {
    let out_buf = vec![{ opcodes::TRAVEL_OPCODE }];

    let in_buf = send_and_receive_sync(out_buf);
    let response: String = rmp_serde::from_slice(&in_buf).expect(
        "Did not receive expected response from the server. This error should be reported.",
    );
    println!("{}", response);
}

fn transaction(opcode: u8, item_id: u8, quantity: u64) {
    let mut out_buf = vec![{ opcode }];
    opcodes::serialize_transaction(item_id, quantity, &mut out_buf);

    let in_buf = send_and_receive_sync(out_buf);
    let response: String = rmp_serde::from_slice(&in_buf).expect(
        "Did not receive expected response from the server. This error should be reported.",
    );
    println!("{}", response);
}

fn buy_items(item_id: u8, quantity: u64) {
    transaction(opcodes::BUY_OPCODE, item_id, quantity);
}

fn sell_items(item_id: u8, quantity: u64) {
    transaction(opcodes::SELL_OPCODE, item_id, quantity);
}

fn index() {
    let out_buf = vec![{ opcodes::INDEX_OPCODE }];

    let in_buf = send_and_receive_sync(out_buf);
    let response: String = rmp_serde::from_slice(&in_buf).expect(
        "Did not receive expected response from the server. This error should be reported.",
    );
    println!("{}", response);
}

fn print_actions() {
    println!("Possible actions:");
    println!("\tbuy");
    println!("\tsell");
    println!("\ttravel");
    println!("\treset");
    println!("\tquit");
}

enum TransactionType {
    Buy,
    Sell,
}
fn handle_transaction(t: TransactionType) {
    use TransactionType::*;
    loop {
        let state = request_goods();
        state.display();
        match t {
            Buy => {
                println!(
                    "Enter the ID of the item you want to buy and the quantity, separated by a \
                    space. Type 'back' to return to the previous menu."
                );
            },
            Sell => {
                println!(
                    "Enter the ID of the item you want to sell and the quantity, separated by a \
                    space. Type 'back' to return to the previous menu."
                );
            },
        }
        let input = get_user_input();
        if input == "back".to_string() {
            return;
        }

        let mut split = input.split_whitespace();
        let item_id_str = match split.next() {
            Some(maybe_id) => maybe_id,
            None => continue,
        };
        let quantity_str = match split.next() {
            Some(maybe_quantity) => maybe_quantity,
            None => continue,
        };

        let item_id: u8 = match item_id_str.parse() {
            Ok(item_id) => item_id,
            Err(_) => continue,
        };
        let quantity: u64 = match quantity_str.parse() {
            Ok(quantity) => quantity,
            Err(_) => continue,
        };

        match t{
            Buy => buy_items(item_id, quantity),
            Sell => sell_items(item_id, quantity),
        }
    }
}

fn get_user_input() -> String {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line. Report this error.");
    input.trim().to_string()
}

fn main() {
    index();

    loop {
        request_state().display();
        println!("What do you want to do?");
        print_actions();
        let input = get_user_input();
        // to_string to shut the IDE up. Not necessary.
        if input == "buy".to_string() {
            handle_transaction(TransactionType::Buy);
        } else if input == "sell".to_string() {
            handle_transaction(TransactionType::Sell);
        } else if input == "travel".to_string() {
            travel()
        } else if input == "reset".to_string() {
            println!("Are you sure you want to reset? Enter 'yes' if so.");
            let input = get_user_input();
            if input == "yes".to_string() {
                reset_game()
            };
        } else if input == "quit".to_string() {
            exit(0)
        };
    }
}

fn encrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

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

fn decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut out_buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut out_buffer);

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
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
