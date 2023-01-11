
// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::exit;

use pbkdf2::{
    password_hash::{rand_core, PasswordHasher, Salt, SaltString},
    Pbkdf2,
};
use sqlite::Value;

const USERDATA: &str = "./local.db";

fn prompt_input(prompt_text: &str) -> String {
    let mut input = String::new();

    print!("{}", prompt_text);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).expect("read_line error");

    input.trim().to_string()
}

type B64HashedPassword = String;
type B64Salt = String;

#[derive(Debug)]
struct UserData {
    username: String,
    hashed_password: B64HashedPassword,
    salt: B64Salt,
    profile_pic: PathBuf,
}

impl UserData {
    pub fn new(username: &str) -> Self {
        Self {
            username: String::from(username),
            hashed_password: String::new(),
            salt: String::new(),
            profile_pic: PathBuf::from("ProfilePlaceholderSuit.svg"),
        }
    }

    pub fn hash_password(
        new_password: &str,
        salt_hex: Option<&str>,
    ) -> Result<(B64HashedPassword, B64Salt), Box<dyn Error>> {
        let generated_salt;
        let salt = match salt_hex {
            Some(v) => Salt::new(v)?,
            None => {
                generated_salt = SaltString::generate(rand_core::OsRng).to_owned();
                Salt::from(&generated_salt)
            }
        };

        let new_hash = Pbkdf2.hash_password(new_password.as_bytes(), &salt)?;

        Ok((new_hash.hash.unwrap().to_string(), salt.to_string()))
    }

    pub fn change_password(
        &mut self,
        new_password: &str,
        salt_hex: Option<&str>,
    ) -> Result<(), Box<dyn Error>> {
        let (b64_hashed_password, b64_salt) = Self::hash_password(new_password, salt_hex)?;
        self.hashed_password = b64_hashed_password;
        self.salt = b64_salt;

        sqlite_update_user_password(&self.username, &self.hashed_password, &self.salt)
    }

    pub fn check_password(&self, password_to_check: &str) -> Result<bool, Box<dyn Error>> {
        let (b64_hashed_password, _b64_salt) =
            Self::hash_password(password_to_check, Some(&self.salt))?;
        Ok(b64_hashed_password == self.hashed_password)
    }

    pub fn change_profile_pic(
        &mut self,
        new_profile_pic_path: PathBuf,
    ) -> Result<(), Box<dyn Error>> {
        self.profile_pic = new_profile_pic_path;

        sqlite_update_profile_pic(&self.username, &self.profile_pic)
    }
}

impl Display for UserData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UserData {{\n\t\
                username: {}\n\t\
                hashed_password: {}\n\t\
                salt: {}\n\t\
                profile_pic: {:?}\n\
            }}",
            self.username, self.hashed_password, self.salt, self.profile_pic
        )
    }
}

fn sqlite_error(message: &str) -> sqlite::Error {
    sqlite::Error {
        code: None,
        message: Some(format!("{} column was not a string.", message)),
    }
}

fn sqlite_update_user_password(
    username: &str,
    new_pw_hash: &str,
    new_salt: &str,
) -> Result<(), Box<dyn Error>> {
    let connection = sqlite::open(USERDATA)?;
    let mut cursor = connection
        .prepare("UPDATE users SET hashed_password = ?, salt = ? WHERE username = ?")?
        .into_cursor();
    cursor.bind(&[
        Value::String(new_pw_hash.to_string()),
        Value::String(new_salt.to_string()),
        Value::String(username.to_string()),
    ])?;

    cursor.next()?;

    Ok(())
}

fn sqlite_update_profile_pic(
    username: &str,
    new_profile_pic_path: &PathBuf,
) -> Result<(), Box<dyn Error>> {
    let connection = sqlite::open(USERDATA)?;
    let mut cursor = connection
        .prepare("UPDATE users SET profile_pic = ? WHERE username = ?")?
        .into_cursor();
    cursor.bind(&[
        Value::String(new_profile_pic_path.to_str().unwrap().to_string()),
        Value::String(username.to_string()),
    ])?;

    cursor.next()?;

    Ok(())
}

fn sqlite_lookup_userdata(username: String) -> Result<Option<UserData>, Box<dyn Error>> {
    let connection = sqlite::open(USERDATA)?;
    let mut cursor = connection
        .prepare("SELECT * FROM users WHERE username = ?")?
        .into_cursor();
    cursor.bind(&[Value::String(username)])?;

    let result = match cursor.next()? {
        Some(row) => Some(UserData {
            username: String::from(row[0].as_string().ok_or(sqlite_error("username"))?),
            hashed_password: String::from(
                row[1].as_string().ok_or(sqlite_error("hashed_password"))?,
            ),
            salt: String::from(row[2].as_string().ok_or(sqlite_error("salt"))?),
            profile_pic: PathBuf::from(row[3].as_string().ok_or(sqlite_error("profile_pic"))?),
        }),
        None => None,
    };
    Ok(result)
}

fn sqlite_new_user(user_data: UserData) -> Result<(), Box<dyn Error>> {
    let connection = sqlite::open(USERDATA)?;
    let mut cursor = connection
        .prepare("INSERT INTO users VALUES (?, ?, ?, ?)")?
        .into_cursor();
    cursor.bind(&[
        Value::String(user_data.username),
        Value::String(user_data.hashed_password),
        Value::String(user_data.salt),
        Value::String(user_data.profile_pic.to_str().unwrap().to_string()),
    ])?;

    cursor.next()?;

    Ok(())
}

fn user_menu(mut user_data: UserData) {
    loop {
        let input = prompt_input(
            "1) Change Password\n\
            2) Change Profile Picture\n\
            3) View Profile Picture\n\
            > ",
        );
        match input.as_str() {
            "1" => {
                let new_password = prompt_input("Enter a new password: ");
                user_data
                    .change_password(new_password.as_str(), None)
                    .unwrap();
            }
            "2" => {
                let pic_input = prompt_input(
                    "1) Machovka_case.svg\n\
                    2) Machovka_Microwave_oven_2.svg\n\
                    3) pgb-chip-generic.svg\n\
                    4) ProfilePlaceholderSuit.svg\n\
                    5) shokunin-tux.svg\n\
                    6) Custom\n\
                    > ",
                );
                let new_pic = match pic_input.as_str() {
                    "1" => "Machovka_case.svg".to_string(),
                    "2" => "Machovka_Microwave_oven_2.svg".to_string(),
                    "3" => "pgb-chip-generic.svg".to_string(),
                    "4" => "ProfilePlaceholderSuit.svg".to_string(),
                    "5" => "shokunin-tux.svg".to_string(),
                    "6" => prompt_input("Enter the path to your profile picture: "),
                    _ => continue,
                };
                user_data
                    .change_profile_pic(PathBuf::from(new_pic))
                    .unwrap();
            }
            "3" => {
                let mut file_path = PathBuf::from("images");
                file_path.push(user_data.profile_pic.clone());
                let mut file = match File::open(file_path) {
                    Ok(f) => f,
                    Err(e) => {
                        println!("{}", e);
                        continue;
                    }
                };
                let mut contents = String::new();
                match file.read_to_string(&mut contents) {
                    Ok(_) => (),
                    Err(e) => println!("{}", e),
                }
                println!("{}", contents);
            }
            _ => continue,
        }
    }
}

fn login() {
    let username = prompt_input("Enter your username: ");
    println!("Welcome {}.", username);

    let user_data = match sqlite_lookup_userdata(username).unwrap() {
        Some(data) => data,
        None => {
            println!("Couldn't find a user with that name. Goodbye.");
            return;
        }
    };

    let password = prompt_input("Enter your password: ");
    if let false = user_data.check_password(&password).unwrap() {
        println!("Password is incorrect for this account. Good bye.");
        return;
    };

    user_menu(user_data);
}

fn register() {
    let username = prompt_input("Enter a username to register: ");
    println!("Welcome {}.", username);

    let mut user_data = UserData::new(username.as_str());

    let password = prompt_input("Enter a password: ");
    user_data.change_password(password.as_str(), None).unwrap();

    sqlite_new_user(user_data).unwrap();
    println!("You may now log in.");
}

fn welcome_menu() {
    println!("Welcome to the user information service.");
    loop {
        let input = prompt_input(
            "1) Login\n\
            2) Register New Users\n\
            Q) Quit\n\
            > ",
        );
        match input.as_str() {
            "1" => login(),
            "2" => register(),
            "Q" | "q" => exit(0),
            _ => continue,
        }
    }
}
fn main() {
    welcome_menu();
}

#[cfg(test)]
mod tests {
    use crate::UserData;
    use std::path::PathBuf;

    #[test]
    fn check_given_password() {
        let b64_hashed_password = "WLPFErhZ2ef3x0VMdovRnMZXQ2o/CZo+RU7B45yEyx8";
        let b64_salt = "VwBonUNijQeXtkdvDSEZzT8AoNEltgyZFNzmYiZfRWQ";

        let user = UserData {
            username: "testuser".to_string(),
            hashed_password: b64_hashed_password.to_string(),
            salt: b64_salt.to_string(),
            profile_pic: PathBuf::from("".to_string()),
        };

        let result = user.check_password("a").unwrap();

        assert!(result);
    }

    #[test]
    fn change_user_pw() {
        let b64_hashed_password = "WLPFErhZ2ef3x0VMdovRnMZXQ2o/CZo+RU7B45yEyx8";
        let b64_salt = "VwBonUNijQeXtkdvDSEZzT8AoNEltgyZFNzmYiZfRWQ";

        let mut user = UserData {
            username: "testuser".to_string(),
            hashed_password: "".to_string(),
            salt: "".to_string(),
            profile_pic: PathBuf::from("".to_string()),
        };

        user.change_password("a", Some(b64_salt)).unwrap();

        assert_eq!(b64_hashed_password, user.hashed_password);
    }

    #[test]
    fn change_user_profile_pic() {
        let pic_path = PathBuf::from("testpic.png");

        let mut user = UserData {
            username: "testuser".to_string(),
            hashed_password: "".to_string(),
            salt: "".to_string(),
            profile_pic: PathBuf::from("".to_string()),
        };

        user.change_profile_pic(pic_path.clone()).unwrap();

        assert_eq!(pic_path, user.profile_pic);
    }
}

