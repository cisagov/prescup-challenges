use std::{io::Read, ops::{Deref, DerefMut}};
use std::os::unix::fs::FileExt;
use dotenvy::dotenv;
use rocket::{Response, data::FromData, fairing::{self, AdHoc, Fairing, Info, Kind}, http::{Header, Status}, serde::{Deserialize, Serialize, json::serde_json}};
use rocket_db_pools::{Connection, Database};
use rocket_dyn_templates::{context, Template};
use rsa::{pkcs8::DecodePublicKey, sha2::Sha256, signature::Verifier};
use sqlx::types::chrono;
use rocket::request::{Request, local_cache};


#[macro_use] extern crate rocket;

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Cross-Origin-Opener-Policy", "same-origin"));
        response.set_header(Header::new("Cross-Origin-Embedder-Policy", "require-corp"));
    }
}

#[derive(Database)]
#[database("sqlx")]
struct Db(sqlx::SqlitePool);

// type DbResult<T, E = rocket::response::Debug<sqlx::Error>> = std::result::Result<T, E>;

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(crate = "rocket::serde")]
struct LeaderboardEntry {
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    rank: Option<i32>,
    name: String,
    score: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<chrono::NaiveDateTime>,
}

const PUBLIC_KEY_STR: &str = r#"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAijF46XNfKyu6+h7jG3Gx
+N4TSqarngHaWDS+Z0K2F9e2o6XM4c815Ix0A1mg8oatuTjrsNWN55lZllUoPc8H
q8/P4QbRP/jWZhu04qHaOt/NxKosskhtJQzlHMaXUZ0KOqoa3qErnFc6+eV59J1n
V8a6t38aG7HiJh93Ga3pC4PO7QG4Z0xk3I+TFpf5o6juphOQxhKRhv3xTi4i/Yoi
YAeocL8egEB57LtcfaicAWGBdzfBdXLFWsrkNA6MVWsj586jsnIkUhp506YVMS7X
HkfGSgxlMWWQ6dGQr9gEk6lXXiQNmKJyVE4JJHv0AMmq3nVmBTfvOt68HQ8nsNcZ
XaleQffo/zWhyL93vuMW12WBCCIYBTWluINgQpjbE3gNmgentqwRk0X7y4pXC8+9
WgMPTHr3RW2sTwLtleL0dSdYdUcF1JE2QlPV66UqCQkW0rDBm2hD6VVKb9gn86ii
eQBhHBKD0MfyUCdbFrfYDou7p52uPo0oAbrDSx2SzllPTLfCA9eiKvM8GaN6kk9B
hhOOmzUthvBk1vVDRknPcOtVnj5QPfr3/kMcFSc0Gg9HWAWa2sIXvgyDsQloEdD9
AaGhJsyVkTfOeTD9nWqKaM9fFrNQwauJ2DKDMgSrPIWchRT7RQCbKlDnOrfCrYld
3v5d+JzQsPJPanmMWrTevPsCAwEAAQ==
-----END PUBLIC KEY-----
"#;

struct SignedJson<T>(T);

impl<T> Deref for SignedJson<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for SignedJson<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0  
    }
}

#[derive(Debug)]
enum SignatureError {
    InvalidSignature(String),
    InvalidData(String),
    UnableToLoadBuffer(String),
    UnableToChunkBuffer(String),
    UnableToDecodeBuffer(String),
    NoDataSignature,
    IncorrectSignature(String),
    InvalidPublicKey,
}

#[rocket::async_trait]
impl<'r, T: Deserialize<'r>> FromData<'r> for SignedJson<T> {
    type Error = SignatureError;

    async fn from_data(req: &'r Request<'_>, data: rocket::Data<'r>) -> rocket::data::Outcome<'r,Self> {
        let Ok(public_key) = rsa::RsaPublicKey::from_public_key_pem(PUBLIC_KEY_STR).map_err(|_| SignatureError::InvalidPublicKey) else {
            return rocket::data::Outcome::Error((rocket::http::Status::InternalServerError, SignatureError::InvalidPublicKey));
        };

        debug!("Public key loaded successfully: {:?}", public_key);

        let data_stream = data.open(rocket::data::ByteUnit::Megabyte(512));

        let buffer_bytes = match data_stream.into_bytes().await {
            Ok(buffer_bytes) => buffer_bytes,
            Err(err) => return rocket::data::Outcome::Error((rocket::http::Status::BadRequest, SignatureError::UnableToLoadBuffer(format!("error: {err:?}")))),
        };
        debug!("Data buffer loaded successfully: {:?}", buffer_bytes);
        let (chunked_buffer, []) = buffer_bytes.as_chunks::<4>() else {
            return rocket::data::Outcome::Error((rocket::http::Status::BadRequest, SignatureError::UnableToChunkBuffer(format!("{:?}", buffer_bytes))));
        };
        debug!("Data buffer chunked successfully: {:?}", chunked_buffer);

        let Some(buffer_string) = chunked_buffer.iter().map(|chunk| char::from_u32(u32::from_be_bytes(*chunk) ^ 0xDEAD)).collect::<Option<String>>() else {
            return rocket::data::Outcome::Error((rocket::http::Status::BadRequest, SignatureError::UnableToDecodeBuffer(format!("{:?}", chunked_buffer))));
        };

        let buffer = buffer_string.bytes().collect::<Vec<u8>>();
        debug!("Data buffer decoded successfully: {:?}", buffer);
        
        let Some(signature_buffer) = req.headers().get_one("Data-Signature")
            .and_then(|s| hex::decode(s).ok()) else {
            return rocket::data::Outcome::Error((rocket::http::Status::BadRequest, SignatureError::NoDataSignature));
        };
        debug!("Signature buffer loaded successfully: {:?}", signature_buffer);

        let signature = match rsa::pkcs1v15::Signature::try_from(signature_buffer.as_slice()) {
            Ok(signature) => signature,
            Err(err) => {
                    return rocket::data::Outcome::Error((rocket::http::Status::BadRequest, SignatureError::InvalidSignature(format!("buffer_string: {buffer_string:?}, error: {err:?}"))));
                }
        };

        debug!("Signature loaded successfully: {:?}", signature);

        let verify_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);

        if let Err(err) = verify_key.verify(&buffer, &signature) {
            return rocket::data::Outcome::Error((rocket::http::Status::Forbidden, SignatureError::IncorrectSignature(format!("buffer_string: {buffer_string:?}, error: {err:?}"))));
        }

        match serde_json::from_slice::<T>(local_cache!(req, buffer)) {
            Ok(res) => rocket::data::Outcome::Success(SignedJson(res)),
            Err(err) => rocket::data::Outcome::Error((rocket::http::Status::BadRequest, SignatureError::InvalidData(format!("buffer_string: {buffer_string:?}, error: {err:?}")))),
        }
    }
}

#[post("/submit", data = "<entry>")]
async fn submit(mut db: Connection<Db>, entry: SignedJson<LeaderboardEntry>) -> Result<(), Status> {
    if entry.score < 0 || entry.name.trim().is_empty() || entry.name.contains("<script>") {
        return Err(Status::Forbidden);
    }

    sqlx::query!(
        "INSERT INTO leaderboard (name, score) VALUES (?, ?)",
        entry.name,
        entry.score
    )
    .execute(&mut **db)
    .await.map_err(|_| Status::InternalServerError)?;

    Ok(())
}

#[get("/leaderboard")]
async fn leaderboard(mut db: Connection<Db>) -> Template {
    let leaderboard = sqlx::query_as!(LeaderboardEntry, "SELECT row_number() OVER (ORDER BY score DESC) AS rank, id, name, score, created_at FROM leaderboard ORDER BY score DESC LIMIT 100")
        .fetch_all(&mut **db)
        .await
        .unwrap_or_default();

    Template::render("leaderboard", context! { leaderboard })
}

async fn run_migrations(rocket: rocket::Rocket<rocket::Build>) -> fairing::Result {
    match Db::fetch(&rocket) {
        Some(db) => match sqlx::migrate!("./migrations").run(&db.0).await {
            Ok(_) => Ok(rocket),
            Err(e) => {
                error!("Failed to run migrations: {e}");
                Err(rocket)
            }
        },

        None => Err(rocket),
    }
}

fn stage_database() -> rocket::fairing::AdHoc {
    AdHoc::on_ignite("Database Stage", |rocket| async {
        rocket.attach(Db::init())
            .attach(AdHoc::try_on_ignite("SQLx Migrations", run_migrations))
    })
}

fn rewrite_with_token(filename: &str) {
    let submit_token = std::env::var("SUBMIT_TOKEN")
        .unwrap_or_else(|_| "PCCC{TESTING-SUBMIT2}".to_string())
        .trim_start_matches("PCCC{")
        .trim_end_matches("}")
        .to_string();
    
    let mut wasm_file = std::fs::OpenOptions::new().read(true).write(true).open(filename).unwrap();
    let mut wasm_buffer = Vec::new();
    wasm_file.read_to_end(&mut wasm_buffer).unwrap();

    const NEEDLE: &[u8] = b"_____TOKEN_____";
    assert!(NEEDLE.len() == submit_token.len(), "Token length mismatch");

    if let Some(start) = wasm_buffer.windows(NEEDLE.len()).position(|w| w == NEEDLE) {
        wasm_file.write_at(submit_token.as_bytes(), start as u64).unwrap();
    } else {
        error!("Token placeholder not found in the wasm binary");
    }
}

#[launch]
fn rocket() -> _ {
    dotenv().unwrap_or_default();
    // Read wasm file and replace the token placeholder in the binary with the generated token
    rewrite_with_token("/app/game/rust.nothreads.wasm");
    rewrite_with_token("/app/game/debug/rust.nothreads.wasm");

    rocket::build()
        .attach(CORS)
        .mount("/", routes![leaderboard, submit])
        .mount("/", rocket::fs::FileServer::from("/app/game").rank(0))
        .mount("/static", rocket::fs::FileServer::from("/app/static").rank(-1))
        .mount("/tools", rocket::fs::FileServer::from("/gdsdecomp").rank(-5))
        .attach(Template::fairing())
        .attach(stage_database())
}
