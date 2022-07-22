// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;

use std::{thread, time};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;

use rand::Rng;
use rocket::State;
use rocket_contrib::json::{Json, JsonValue};

const BODYGUARD_MIN_COST: u128 = 70;
const BODYGUARD_MAX_COST: u128 = 130;
const STAPLE_GOODS_MIN_COST: u128 = 100;
const STAPLE_GOODS_MAX_COST: u128 = 110;
const LUXURY_GOODS_MIN_COST: u128 = 400;
const LUXURY_GOODS_MAX_COST: u128 = 700;
const WEAPONS_MIN_COST: u128 = 250;
const WEAPONS_MAX_COST: u128 = 350;
const ARMOR_MIN_COST: u128 = 350;
const ARMOR_MAX_COST: u128 = 450;

// 9 x 10^25
const CHALLENGE_FLAG_MIN_COST: u128 = 90000000000000000000000000;
// 10^38
const CHALLENGE_FLAG_MAX_COST: u128 = 100000000000000000000000000000000000000;

const STAPLE_GOODS_MIN_SELL: u128 = 115;
const STAPLE_GOODS_MAX_SELL: u128 = 130;
const LUXURY_GOODS_MIN_SELL: u128 = 300;
const LUXURY_GOODS_MAX_SELL: u128 = 1000;
const WEAPONS_MIN_SELL: u128 = 300;
const WEAPONS_MAX_SELL: u128 = 500;
const ARMOR_MIN_SELL: u128 = 400;
const ARMOR_MAX_SELL: u128 = 650;

const BANDIT_SMALL_CHANCE: u8 = 10;
const BANDIT_SMALL_BODYGUARDS: u128 = 2;
const BANDIT_MEDIUM_CHANCE: u8 = 5;
const BANDIT_MEDIUM_BODYGUARDS: u128 = 5;
const BANDIT_LARGE_CHANCE: u8 = 1;
const BANDIT_LARGE_BODYGUARDS: u128 = 10;

const INVENTORY_LIMIT: u128 = 100;
const BODYGUARD_LIMIT: u128 = 10;

#[derive(Serialize)]
enum Goods {
    Bodyguard = 0,
    StapleGoods = 1,
    LuxuryGoods = 2,
    Weapon = 3,
    Armor = 4,
    ChallengeFlag = 5,
}

impl Goods {
    fn from_u8(id: u8) -> Option<Goods> {
        use Goods::*;

        match id {
            x if x == Bodyguard as u8 => Some(Bodyguard),
            x if x == StapleGoods as u8 => Some(StapleGoods),
            x if x == LuxuryGoods as u8 => Some(LuxuryGoods),
            x if x == Weapon as u8 => Some(Weapon),
            x if x == Armor as u8 => Some(Armor),
            x if x == ChallengeFlag as u8 => Some(ChallengeFlag),
            _ => None,
        }
    }
}

enum BuyResult {
    Success,
    NotEnoughMoney,
    BodyguardLimit,
    ItemLimit,
    FlagPurchased,
}

enum SellResult {
    Success,
    CannotSell,
    NotEnoughItems,
}

enum TravelResult {
    Arrived,
    RobbedByBandits,
    DiedToBandits,
}

#[derive(Clone, Debug, Serialize)]
struct GameState {
    money: u128,

    bodyguard_amt: u128,
    staple_goods_amt: u128,
    luxury_goods_amt: u128,
    weapons_amt: u128,
    armor_amt: u128,

    bodyguard_buy_price: u128,
    challenge_flag_buy_price: u128,
    staple_goods_buy_price: u128,
    luxury_goods_buy_price: u128,
    weapons_buy_price: u128,
    armor_buy_price: u128,

    staple_goods_sell_price: u128,
    luxury_goods_sell_price: u128,
    weapons_sell_price: u128,
    armor_sell_price: u128,
}

fn generate_new_challenge_price() -> u128 {
    let mut rng = rand::thread_rng();
    // gen_range is an inclusive, exclusive interval, hence the + 1.
    2 * rng.gen_range(CHALLENGE_FLAG_MIN_COST, CHALLENGE_FLAG_MAX_COST + 1)
}

impl GameState {
    fn new() -> Self {
        Self {
            money: 10000,
            bodyguard_amt: 0,
            staple_goods_amt: 0,
            luxury_goods_amt: 0,
            weapons_amt: 0,
            armor_amt: 0,
            bodyguard_buy_price: BODYGUARD_MIN_COST,
            challenge_flag_buy_price: generate_new_challenge_price(),
            staple_goods_buy_price: STAPLE_GOODS_MIN_COST,
            luxury_goods_buy_price: LUXURY_GOODS_MIN_COST,
            weapons_buy_price: WEAPONS_MIN_COST,
            armor_buy_price: ARMOR_MIN_COST,
            staple_goods_sell_price: STAPLE_GOODS_MIN_COST,
            luxury_goods_sell_price: LUXURY_GOODS_MIN_COST,
            weapons_sell_price: WEAPONS_MIN_COST,
            armor_sell_price: ARMOR_MIN_COST,
        }
    }

    fn reset(&mut self) {
        let new_state = Self::new();
        self.clone_from(&new_state);
    }

    fn current_inventory(&self) -> u128 {
        self.armor_amt + self.weapons_amt + self.luxury_goods_amt + self.staple_goods_amt
    }

    fn buy_items(&mut self, item_id: Goods, number: u128) -> BuyResult {
        use BuyResult::*;
        use Goods::*;

        if number == 0 {
            return Success;
        }

        let cost = match item_id {
            Bodyguard => self.bodyguard_buy_price,
            ChallengeFlag => {
                self.challenge_flag_buy_price = generate_new_challenge_price();
                self.challenge_flag_buy_price
            },
            StapleGoods => self.staple_goods_buy_price,
            LuxuryGoods => self.luxury_goods_buy_price,
            Weapon => self.weapons_buy_price,
            Armor => self.armor_buy_price,
        };

        // This is an unchecked multiplication in Release versions of Rust, meaning a potential
        // integer overflow.
        let total_cost = number * cost;
        if total_cost > self.money {
            return NotEnoughMoney;
        }

        // Enforce bodyguard/inventory limits. Challenge Flag is unique and does not consume money.
        match item_id {
            Bodyguard => {
                if self.bodyguard_amt + number > BODYGUARD_LIMIT {
                    return BodyguardLimit;
                }
            }
            ChallengeFlag => return FlagPurchased,
            _ => {
                if self.current_inventory() + number > INVENTORY_LIMIT {
                    return ItemLimit;
                }
            }
        };

        // All checks passed. Give the requested number of bodyguards/items and deduct the cost.
        match item_id {
            Bodyguard => self.bodyguard_amt += number,
            StapleGoods => {
                self.staple_goods_amt += number;
                self.staple_goods_sell_price = self.staple_goods_buy_price;
            }
            LuxuryGoods => {
                self.luxury_goods_amt += number;
                self.luxury_goods_sell_price = self.luxury_goods_buy_price;
            }
            Weapon => {
                self.weapons_amt += number;
                self.weapons_sell_price = self.weapons_buy_price;
            }
            Armor => {
                self.armor_amt += number;
                self.armor_sell_price = self.armor_buy_price;
            }
            ChallengeFlag => unreachable!(),
        };
        self.money -= total_cost;

        Success
    }

    fn sell_items(&mut self, item_id: Goods, number: u128) -> SellResult {
        use Goods::*;
        use SellResult::*;

        match item_id {
            Bodyguard => return CannotSell,
            ChallengeFlag => return CannotSell,
            StapleGoods => {
                if self.staple_goods_amt < number {
                    return NotEnoughItems;
                }
            }
            LuxuryGoods => {
                if self.luxury_goods_amt < number {
                    return NotEnoughItems;
                }
            }
            Weapon => {
                if self.weapons_amt < number {
                    return NotEnoughItems;
                }
            }
            Armor => {
                if self.armor_amt < number {
                    return NotEnoughItems;
                }
            }
        };

        let sell_price = match item_id {
            StapleGoods => {
                self.staple_goods_amt -= number;
                self.staple_goods_buy_price = self.staple_goods_sell_price;
                self.staple_goods_sell_price
            }
            LuxuryGoods => {
                self.luxury_goods_amt -= number;
                self.luxury_goods_buy_price = self.luxury_goods_sell_price;
                self.luxury_goods_sell_price
            }
            Weapon => {
                self.weapons_amt -= number;
                self.weapons_buy_price = self.weapons_sell_price;
                self.weapons_sell_price
            }
            Armor => {
                self.armor_amt -= number;
                self.armor_buy_price = self.armor_sell_price;
                self.armor_sell_price
            }
            _ => unreachable!(),
        };

        self.money += sell_price * number;
        Success
    }

    fn travel(&mut self) -> TravelResult {
        use TravelResult::*;

        let mut rng = rand::thread_rng();

        self.staple_goods_buy_price =
            rng.gen_range(STAPLE_GOODS_MIN_COST, STAPLE_GOODS_MAX_COST + 1);
        self.staple_goods_sell_price =
            rng.gen_range(STAPLE_GOODS_MIN_SELL, STAPLE_GOODS_MAX_SELL + 1);

        self.luxury_goods_buy_price =
            rng.gen_range(LUXURY_GOODS_MIN_COST, LUXURY_GOODS_MAX_COST + 1);
        self.luxury_goods_sell_price =
            rng.gen_range(LUXURY_GOODS_MIN_SELL, LUXURY_GOODS_MAX_SELL + 1);

        self.weapons_buy_price = rng.gen_range(WEAPONS_MIN_COST, WEAPONS_MAX_COST + 1);
        self.weapons_sell_price = rng.gen_range(WEAPONS_MIN_SELL, WEAPONS_MAX_SELL + 1);

        self.armor_buy_price = rng.gen_range(ARMOR_MIN_COST, ARMOR_MAX_COST + 1);
        self.armor_sell_price = rng.gen_range(ARMOR_MIN_SELL, ARMOR_MAX_SELL + 1);

        let sleep_millis = rng.gen_range(1000, 3001);
        let travel_time = time::Duration::from_millis(sleep_millis);
        thread::sleep(travel_time);

        let bandit_roll = rng.gen_range(0, 100);
        let mut death_threshold = 0;
        let mut robbed_threshold = 0;
        match bandit_roll {
            x if x < BANDIT_LARGE_CHANCE => {
                death_threshold = BANDIT_MEDIUM_BODYGUARDS;
                robbed_threshold = BANDIT_LARGE_BODYGUARDS;
            }
            x if x < BANDIT_LARGE_CHANCE + BANDIT_MEDIUM_CHANCE => {
                death_threshold = BANDIT_SMALL_BODYGUARDS;
                robbed_threshold = BANDIT_MEDIUM_BODYGUARDS;
            }
            x if x < BANDIT_LARGE_CHANCE + BANDIT_MEDIUM_CHANCE + BANDIT_SMALL_CHANCE => {
                robbed_threshold = BANDIT_SMALL_BODYGUARDS;
            }
            _ => (),
        }

        if self.bodyguard_amt < death_threshold {
            self.reset();
            return DiedToBandits;
        } else if self.bodyguard_amt < robbed_threshold {
            self.money /= 2;
            self.luxury_goods_amt /= 2;
            self.staple_goods_amt /= 2;
            self.weapons_amt /= 2;
            self.armor_amt /= 2;
            self.bodyguard_amt = 0;
            return RobbedByBandits;
        }
        self.bodyguard_amt = 0;
        Arrived
    }
}

type MutexGameState = Mutex<GameState>;

// Prices and PricesList structs had to be implemented to workaround the json!() macro's limitation
// of u128s.
#[derive(Serialize)]
struct Prices {
    id: u8,
    buy: u128,
    sell: Option<u128>,
}

impl Prices {
    fn from(id: u8, buy: u128, sell: Option<u128>) -> Self {
        Self{id, buy, sell}
    }
}

#[derive(Serialize)]
struct PricesList {
    bodyguards: Prices,
    staple_goods: Prices,
    luxury_goods: Prices,
    weapon: Prices,
    armor: Prices,
    challenge_flag: Prices,
}

impl PricesList {
    fn from(bodyguards: Prices, staple_goods: Prices, luxury_goods: Prices, weapon: Prices, armor: Prices, challenge_flag: Prices) -> Self {
        Self{bodyguards, staple_goods, luxury_goods, weapon, armor, challenge_flag}
    }
}

#[get("/")]
fn index() -> String {
    format!("Welcome to a very basic game! In this game you will attempt to\n\
             make a profit by trading between towns. Beware, however, as\n\
             bandits will be trying to make a profit by preying on you!\n\
             Hire bodyguards in order to protect yourself from bandits.\n\
             You can have {} guards at a time. If you are short on bodyguards,\n\
             the fiends will certainly take as much as they can, and may\n\
             even kill you if they think it will be easy for them!",
             BODYGUARD_LIMIT)
}

#[get("/goods")]
fn goods(wrapped_state: State<'_, MutexGameState>) -> Json<PricesList> {
    let game_state = wrapped_state.lock().unwrap().clone();

    let bodyguards = Prices::from(Goods::Bodyguard as u8, game_state.bodyguard_buy_price, None);
    let staple_goods = Prices::from(Goods::StapleGoods as u8, game_state.staple_goods_buy_price, Some(game_state.staple_goods_sell_price));
    let luxury_goods = Prices::from(Goods::LuxuryGoods as u8, game_state.luxury_goods_buy_price, Some(game_state.luxury_goods_sell_price));
    let weapon = Prices::from(Goods::Weapon as u8, game_state.weapons_buy_price, Some(game_state.weapons_sell_price));
    let armor = Prices::from(Goods::Armor as u8, game_state.armor_buy_price, Some(game_state.armor_sell_price));
    let challenge_flag = Prices::from(Goods::ChallengeFlag as u8, game_state.challenge_flag_buy_price, None);

    let prices_list = PricesList::from(bodyguards, staple_goods, luxury_goods, weapon, armor, challenge_flag);

    Json(prices_list)
}

#[get("/buy/<item_id>/<quantity>")]
fn buy(item_id: u8, quantity: u128, wrapped_state: State<'_, MutexGameState>) -> JsonValue {
    use BuyResult::*;
    let mut game_state = wrapped_state.lock().unwrap();
    let buy_result = match Goods::from_u8(item_id) {
        Some(good) => game_state.buy_items(good, quantity),
        None => return json!({"status": "Invalid item ID."}),
    };

    match buy_result {
        Success => json!({"status": "Purchase successful."}),
        NotEnoughMoney => json!({"status": "Cannot afford purchase."}),
        BodyguardLimit => json!({"status": "You cannot hire that many bodyguards."}),
        ItemLimit => json!({"status": "You cannot carry that many items."}),
        FlagPurchased => {
            match retrieve_flag() {
                Ok(flag) => json!({"status": flag.trim()}),
                Err(_) => json!({"status": "ERROR: Unable to retrieve your flag. Please \
                    report this error to prescup-support@sei.cmu.edu with your support code and a \
                    step-by-step walkthrough of the exploit you used in enough detail that we can \
                    reproduce it and manually award points."})
            }
        },
    }
}

#[get("/sell/<item_id>/<quantity>")]
fn sell(item_id: u8, quantity: u128, wrapped_state: State<'_, MutexGameState>) -> JsonValue {
    use SellResult::*;
    let mut game_state = wrapped_state.lock().unwrap();
    let sell_result = match Goods::from_u8(item_id) {
        Some(good) => game_state.sell_items(good, quantity),
        None => return json!({"status": "Invalid item ID."}),
    };

    match sell_result {
        Success => json!({"status": "Sale successful."}),
        NotEnoughItems => json!({"status": "You don't have enough items."}),
        CannotSell => json!({"status": "You can't sell that type."}),
    }
}

#[get("/travel")]
fn travel(wrapped_state: State<'_, MutexGameState>) -> JsonValue {
    use TravelResult::*;
    let mut game_state = wrapped_state.lock().unwrap();

    match game_state.travel() {
        Arrived => json!({"status": "You have arrived in the next town safely."}),
        RobbedByBandits => {
            json!({"status": "On the way to the next town, you were moderately outnumbered by \
                bandits. You were able to cut a deal with them - in exchange for half of \
                everything you were carrying, you would see another day."})
        }
        DiedToBandits => {
            json!({"status": "On the way to the next town, you were vastly outnumbered by bandits. \
            With their numbers advantage, they simply killed you and your bodyguards and took \
            everything you had. RIP."})
        }
    }
}

#[get("/state")]
fn state(wrapped_state: State<'_, MutexGameState>) -> Json<GameState> {
    let game_state = wrapped_state.lock().unwrap();
    Json(game_state.clone())
}

#[get("/reset")]
fn reset(wrapped_state: State<'_, MutexGameState>) -> JsonValue {
    let mut game_state = wrapped_state.lock().unwrap();
    game_state.reset();
    json!({ "status": "ok" })
}

#[catch(404)]
fn not_found() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Resource was not found or the program did not accept the input."
    })
}

fn retrieve_flag() -> Result<String, String> {
    let path  = Path::new("flag.txt");

    let mut file = match File::open(&path) {
        Err(reason) => return Err(reason.to_string()),
        Ok(file) => file,
    };

    let mut flag = String::new();
    match file.read_to_string(&mut flag) {
        Err(reason) => Err(reason.to_string()),
        Ok(_) => Ok(flag),
    }
}

fn main() {
    rocket::ignite()
        .mount("/", routes![index, buy, goods, reset, sell, state, travel])
        .manage(Mutex::new(GameState::new()))
        .register(catchers![not_found])
        .launch();
}
