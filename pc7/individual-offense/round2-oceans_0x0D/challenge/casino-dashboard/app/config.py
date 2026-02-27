import os
from dataclasses import dataclass

def _env(name: str, default: str="") -> str:
    return os.getenv(name, default)

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    return default if v is None or v.strip()=="" else int(v)

@dataclass(frozen=True)
class Settings:
    vault_core_url: str
    ui_event_buffer: int
    ui_poll_fallback_ms: int
    ui_degraded_banner: bool
    ui_blueprint_reveal_seconds: int
    ui_ghost_reveal_seconds: int
    ui_falsefloor_reveal_seconds: int
    log_json: bool
    log_level: str

def load_settings() -> Settings:
    return Settings(
        vault_core_url=_env("VAULT_CORE_URL","http://vaultcore.pccc:8080"),
        ui_event_buffer=_env_int("UI_EVENT_BUFFER",250),
        ui_poll_fallback_ms=_env_int("UI_POLL_FALLBACK_MS",900),
        ui_degraded_banner=_env("UI_DEGRADED_BANNER","true").lower()=="true",
        ui_blueprint_reveal_seconds=_env_int("UI_BLUEPRINT_REVEAL_SECONDS",8),
        ui_ghost_reveal_seconds=_env_int("UI_GHOST_REVEAL_SECONDS",8),
        ui_falsefloor_reveal_seconds=_env_int("UI_FALSEFLOOR_REVEAL_SECONDS",10),
        log_json=_env("LOG_JSON","true").lower()=="true",
        log_level=_env("LOG_LEVEL","INFO"),
    )
