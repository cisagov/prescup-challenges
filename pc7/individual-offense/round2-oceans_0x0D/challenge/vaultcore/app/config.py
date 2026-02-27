from __future__ import annotations
import os
from dataclasses import dataclass

def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return default if v is None else v

def _env_any(*names: str, default: str = "") -> str:
    for n in names:
        v = os.getenv(n)
        if v is not None and v.strip() != "":
            return v
    return default

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    return default if v is None or v.strip()=="" else int(v)

def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    return default if v is None or v.strip()=="" else float(v)

@dataclass(frozen=True)
class Settings:
    heist_code: str
    env: str

    mqtt_host: str
    mqtt_port: int
    mqtt_client_id: str
    mqtt_keepalive: int
    mqtt_base_topic: str

    vault_boot_seed_b64: str
    vault_master_secret_b64: str

    ctfd_token_1: str
    ctfd_token_2: str
    ctfd_token_3: str
    ctfd_token_4: str

    # Token 1
    t1_bucket_seconds: int
    t1_accept_bucket_slop: int
    t1_rhythm_sig_bytes: int
    t1_encoding_mode: str
    t1_bitrate_bpm: int
    t1_jitter_ms: int
    t1_noise_rate_per_sec: int
    t1_decoy_strength: int
    t1_sync_grace_ms: int
    t1_sync_max_attempts_per_bucket: int

    # Token 2
    t2_max_uploads_per_min: int
    t2_max_upload_bytes: int
    t2_alert_penalty_bad_fw: float
    t2_alert_penalty_fw_spam: float
    t2_require_alert_max: int
    t2_release_version: str
    t2_release_id: str
    t2_sig_algo: str

    # Token 3
    t3_replay_port: int
    t3_pie: str
    t3_max_submits_per_min: int
    t3_max_frame_bytes: int
    t3_alert_penalty_bad_frame: float
    t3_alert_penalty_spam: float
    t3_require_alert_max: int
    t3_proof_ttl_seconds: int

    # Token 4
    t4_max_exports_per_min: int
    t4_max_export_bytes: int
    t4_alert_penalty_bad_export: float
    t4_alert_penalty_export_spam: float
    t4_require_token3: bool
    t4_requires_alert_max: int
    t4_stego_lsb_bits: int
    t4_cipher_block: int

    # Alert
    alert_decay_per_sec: float
    alert_level_thresholds: list[int]
    alert_penalty_bad_sync: float
    alert_penalty_rate_limit: float
    alert_penalty_topic_enum_suspect: float
    alert_level5_mode: str
    lockdown_seconds: int

    # Reveal
    token_reveal_mode: str
    token_reveal_seconds: int
    token_reveal_requires_alert_max: int
    token_reveal_once: bool

    # HTTP RL
    rl_sync_per_min: int
    rl_sync_burst: int

    # Storage/logging
    db_path: str
    log_json: bool
    log_level: str

    # Additional (TOKEN1) variable
    rhythm_bucket_seconds: int = int(os.getenv("RHYTHM_BUCKET_SECONDS", "45"))


def load_settings() -> Settings:
    thresholds_raw = _env("ALERT_LEVEL_THRESHOLDS", "0,10,25,45,70,90")
    thresholds = [int(x.strip()) for x in thresholds_raw.split(",") if x.strip()]
    return Settings(
        heist_code=_env("O13_HEIST_CODE", "OCEANS_0x0D"),
        env=_env("O13_ENV", "prod"),

        mqtt_host=_env("MQTT_HOST", "roulette-telemetry.pccc"),
        mqtt_port=_env_int("MQTT_PORT", 1883),
        mqtt_client_id=_env("MQTT_CLIENT_ID", "o13-vault-core"),
        mqtt_keepalive=_env_int("MQTT_KEEPALIVE", 30),
        mqtt_base_topic=_env("MQTT_BASE_TOPIC", "casino/cage"),

        vault_boot_seed_b64=_env("VAULT_BOOT_SEED_B64", ""),
        vault_master_secret_b64=_env("VAULT_MASTER_SECRET_B64", ""),

        ctfd_token_1=_env_any("CTFD_TOKEN_1", "token1", "TOKEN1", default=""),
        ctfd_token_2=_env_any("CTFD_TOKEN_2", "token2", "TOKEN2", default=""),
        ctfd_token_3=_env_any("CTFD_TOKEN_3", "token3", "TOKEN3", default=""),
        ctfd_token_4=_env_any("CTFD_TOKEN_4", "token4", "TOKEN4", default=""),


        t1_bucket_seconds=_env_int("T1_BUCKET_SECONDS", 30),
        t1_accept_bucket_slop=_env_int("T1_ACCEPT_BUCKET_SLOP", 1),
        t1_rhythm_sig_bytes=_env_int("T1_RHYTHM_SIG_BYTES", 12),
        t1_encoding_mode=_env("T1_ENCODING_MODE", "timing"),
        t1_bitrate_bpm=_env_int("T1_BITRATE_BPM", 240),
        t1_jitter_ms=_env_int("T1_JITTER_MS", 110),
        t1_noise_rate_per_sec=_env_int("T1_NOISE_RATE_PER_SEC", 12),
        t1_decoy_strength=_env_int("T1_DECOY_STRENGTH", 2),
        t1_sync_grace_ms=_env_int("T1_SYNC_GRACE_MS", 900),
        t1_sync_max_attempts_per_bucket=_env_int("T1_SYNC_MAX_ATTEMPTS_PER_BUCKET", 2),

        t2_max_uploads_per_min=_env_int("T2_MAX_UPLOADS_PER_MIN", 4),
        t2_max_upload_bytes=_env_int("T2_MAX_UPLOAD_BYTES", 400000),
        t2_alert_penalty_bad_fw=_env_float("T2_ALERT_PENALTY_BAD_FW", 8.0),
        t2_alert_penalty_fw_spam=_env_float("T2_ALERT_PENALTY_FW_SPAM", 5.0),
        t2_require_alert_max=_env_int("T2_REQUIRE_ALERT_MAX", 3),
        t2_release_version=_env("T2_RELEASE_VERSION", "2.4.7"),
        t2_release_id=_env("T2_RELEASE_ID", ""),
        t2_sig_algo=_env("T2_SIG_ALGO", "HMAC-SHA256"),

        t3_replay_port=_env_int("T3_REPLAY_PORT", 9093),
        t3_pie=_env("T3_PIE", "on"),
        t3_max_submits_per_min=_env_int("T3_MAX_SUBMITS_PER_MIN", 6),
        t3_max_frame_bytes=_env_int("T3_MAX_FRAME_BYTES", 4096),
        t3_alert_penalty_bad_frame=_env_float("T3_ALERT_PENALTY_BAD_FRAME", 6.0),
        t3_alert_penalty_spam=_env_float("T3_ALERT_PENALTY_SPAM", 5.0),
        t3_require_alert_max=_env_int("T3_REQUIRE_ALERT_MAX", 3),
        t3_proof_ttl_seconds=_env_int("T3_PROOF_TTL_SECONDS", 45),

        t4_max_exports_per_min=_env_int("T4_MAX_EXPORTS_PER_MIN", 4),
        t4_max_export_bytes=_env_int("T4_MAX_EXPORT_BYTES", 800000),
        t4_alert_penalty_bad_export=_env_float("T4_ALERT_PENALTY_BAD_EXPORT", 6.0),
        t4_alert_penalty_export_spam=_env_float("T4_ALERT_PENALTY_EXPORT_SPAM", 4.0),
        t4_require_token3=_env("T4_REQUIRE_TOKEN3", "true").lower()=="true",
        t4_requires_alert_max=_env_int("T4_REQUIRES_ALERT_MAX", 3),
        t4_stego_lsb_bits=_env_int("T4_STEGO_LSB_BITS", 1),
        t4_cipher_block=_env_int("T4_CIPHER_BLOCK", 32),

        alert_decay_per_sec=_env_float("ALERT_DECAY_PER_SEC", 0.18),
        alert_level_thresholds=thresholds,
        alert_penalty_bad_sync=_env_float("ALERT_PENALTY_BAD_SYNC", 7.0),
        alert_penalty_rate_limit=_env_float("ALERT_PENALTY_RATE_LIMIT", 4.0),
        alert_penalty_topic_enum_suspect=_env_float("ALERT_PENALTY_TOPIC_ENUM_SUSPECT", 2.5),
        alert_level5_mode=_env("ALERT_LEVEL5_MODE", "cooldown"),
        lockdown_seconds=_env_int("LOCKDOWN_SECONDS", 180),

        token_reveal_mode=_env("TOKEN_REVEAL_MODE", "both"),
        token_reveal_seconds=_env_int("TOKEN_REVEAL_SECONDS", 8),
        token_reveal_requires_alert_max=_env_int("TOKEN_REVEAL_REQUIRES_ALERT_MAX", 3),
        token_reveal_once=_env("TOKEN_REVEAL_ONCE", "false").lower()=="true",

        rl_sync_per_min=_env_int("RL_SYNC_PER_MIN", 10),
        rl_sync_burst=_env_int("RL_SYNC_BURST", 4),

        db_path=_env("DB_PATH", "/tmp/vault.db"),
        log_json=_env("LOG_JSON", "true").lower()=="true",
        log_level=_env("LOG_LEVEL", "INFO"),
    )
