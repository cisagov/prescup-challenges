use godot::classes::hashing_context::HashType;
use godot::prelude::*;
use godot::classes::{AudioStreamPlayer2D, CanvasLayer, ICanvasLayer, RichTextLabel, LineEdit};

#[derive(GodotClass)]
#[class(init, base=CanvasLayer)]
pub struct HudEnd {
    score: i32,
    base: Base<CanvasLayer>,
}

impl super::HudState for HudEnd {
    fn begin(&mut self) {
        self.base().get_node_as::<AudioStreamPlayer2D>("DeathSound").play();
        self.base().get_node_as::<RichTextLabel>("Output").set_text(&format!("[u]Final Score[/u]\n{}", self.score));
    }

    fn end(&mut self) {
        self.base().get_node_as::<AudioStreamPlayer2D>("DeathSound").stop();
    }
}

const PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"#;

// This token will be automatically replaced at runtime by the server
const TOKEN: &str = "_____TOKEN_____";

#[godot_api]
impl HudEnd {
    #[signal]
    fn finish();

    #[func]
    pub fn update_score(&mut self, score: i32) {
        self.score = score;
    }

    #[func]
    #[allow(unused_variables)]
    fn submit_to_leaderboard_complete(&mut self, result: i64, response_code: i64, headers: PackedStringArray, body: PackedByteArray) {
        godot_dbg!("{result} {response_code} {headers} {body}");
        self.signals().finish().emit();
    }

    #[func]
    fn submit_to_leaderboard(&self) {
        let name = self.base().get_node_as::<LineEdit>("Name").get_text();
        let data = (vdict! {
            "name": name,
            "score": self.score,
            "token": TOKEN,
        }).to_variant();
        let json = godot::classes::Json::stringify(&data);
        let mut key = godot::classes::CryptoKey::new_gd();
        // godot_dbg!("Loading private key: {PRIVATE_KEY}");
        key.load_from_string_ex(PRIVATE_KEY).public_only(false).done();
        let mut crypto = godot::classes::Crypto::new_gd();
        let signature = crypto.sign(HashType::SHA256, &json.sha256_buffer(), &key);
        let json = json.chars().iter().flat_map(|c| (u32::from(*c) ^ 0xDEAD).to_be_bytes()).collect();
        godot_dbg!("Submitting to leaderboard: {}", json);
        let mut http_request = self.base().get_node_as::<godot::classes::HttpRequest>("HTTPRequest");
        http_request
            .request_raw_ex("https://dodgethecreeps/submit")
            .method(godot::classes::http_client::Method::POST)
            .custom_headers(&PackedStringArray::from(&[
                "User-Agent: DodgedTheCreepsGameAgent".into(),
                (&format!("Data-Signature: {}", signature.hex_encode())).into(),
                "Content-Type: application/dtc+binary".into(),
            ]))
            .request_data_raw(&json)
            .done();
    }
}

#[godot_api]
impl ICanvasLayer for HudEnd {
    fn ready(&mut self) {
        godot_dbg!("HUDEnd ready: is_visible = {}", self.base().is_visible());
    }
}