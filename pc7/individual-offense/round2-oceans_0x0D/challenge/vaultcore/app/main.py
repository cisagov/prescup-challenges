from __future__ import annotations

import asyncio
import base64
import logging
import os
import signal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import APIRouter

from .config import load_settings
from .logging_setup import setup_logging
from .db import DB
from .alert import AlertEngine
from .rate_limit import TokenBucketLimiter
from .state import VaultState
from .token_dispense import TokenDispenser, TokenConfig
from .routes import router
from .mqtt_client import MqttClient
from .telemetry import CasinoTelemetry
from .casino_games import CasinoGamesEmitter
from .shift_rhythm import ShiftRhythmEmitter, RhythmSettings

log = logging.getLogger("vault")

async def _spawn_replayd(app: FastAPI) -> None:
    settings = app.state.settings
    vault: VaultState = app.state.vault
    assert vault.t3_ghost_secret is not None

    bind = f"127.0.0.1:{settings.t3_replay_port}"
    secret_b64 = base64.b64encode(vault.t3_ghost_secret).decode()

    # Difficulty knob: PIE (harder) vs no-PIE (easier).
    bin_path = "/app/bin/replayd"
    if settings.t3_pie.lower() not in ("on","true","1"):
        if os.path.exists("/app/bin/replayd_nopie"):
            bin_path = "/app/bin/replayd_nopie"

    # Scrub environment before spawning the native helper so injected CTF tokens
    # are not present in the helper process environment even if it is compromised.
    clean_env = {
        "PATH": os.getenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "LANG": os.getenv("LANG", "C.UTF-8"),
        "LC_ALL": os.getenv("LC_ALL", "C.UTF-8"),
    }

    proc = await asyncio.create_subprocess_exec(
        bin_path, bind, secret_b64,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=clean_env,
    )
    app.state.replayd_proc = proc
    log.info("replayd_spawned", extra={"bin": bin_path, "bind": bind, "pid": proc.pid})

    async def pump(name: str, stream):
        while True:
            line = await stream.readline()
            if not line:
                break
            log.info("replayd_log", extra={"stream": name, "line": line.decode(errors="replace").rstrip()})

    asyncio.create_task(pump("stdout", proc.stdout))
    asyncio.create_task(pump("stderr", proc.stderr))

    async def watch():
        rc = await proc.wait()
        log.error("replayd_exited", extra={"rc": rc})
        # Auto-respawn unless we are shutting down.
        if getattr(app.state, "shutdown_in_progress", False):
            return
        await asyncio.sleep(1.0)
        try:
            await _spawn_replayd(app)
        except Exception as e:
            log.error("replayd_respawn_failed", extra={"err": str(e)})
    asyncio.create_task(watch())

def create_app() -> FastAPI:
    settings = load_settings()
    
    log.info("mqtt_config", extra={
    "host": settings.mqtt_host,
    "port": settings.mqtt_port,
    "base_topic": settings.mqtt_base_topic,
    "client_id": settings.mqtt_client_id,
    })

    setup_logging(settings.log_level, settings.log_json)

    app = FastAPI(title="Ocean's 0x0D Vault Core", version="4.0.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.shutdown_in_progress = False
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET","POST"], allow_headers=["*"])

    db = DB(settings.db_path)
    vault = VaultState(db, settings.vault_master_secret_b64, settings.vault_boot_seed_b64)

    alert = AlertEngine(
        decay_per_sec=settings.alert_decay_per_sec,
        thresholds=settings.alert_level_thresholds,
        level5_mode=settings.alert_level5_mode,
        lockdown_seconds=settings.lockdown_seconds,
    )

    limiter_sync = TokenBucketLimiter(settings.rl_sync_per_min, settings.rl_sync_burst)
    limiter_fw = TokenBucketLimiter(settings.t2_max_uploads_per_min, 2)
    limiter_t3 = TokenBucketLimiter(settings.t3_max_submits_per_min, 2)
    limiter_t4 = TokenBucketLimiter(settings.t4_max_exports_per_min, 2)

    mqtt = MqttClient(
      host=settings.mqtt_host,
      port=settings.mqtt_port,
      client_id=f"{settings.mqtt_client_id}-{os.getpid()}",
      base_topic=settings.mqtt_base_topic,
      keepalive=settings.mqtt_keepalive,
    )

    app.state.mqtt = mqtt


    app.state.settings = settings
    app.state.db = db
    app.state.vault = vault
    app.state.alert = alert
    app.state.limiter_sync = limiter_sync
    app.state.limiter_fw = limiter_fw
    app.state.limiter_t3 = limiter_t3
    app.state.limiter_t4 = limiter_t4
    app.state.mqtt = mqtt

    @app.on_event("startup")
    async def _startup():
        await db.connect()
        await vault.load_or_init()
        await alert.start()
        await mqtt.start()

        # 🔐 REQUIRED: initialize dispenser early and unconditionally
        assert vault.secrets is not None

        app.state.dispenser = TokenDispenser(
            TokenConfig(
                ctfd_token_1=settings.ctfd_token_1,
                ctfd_token_2=settings.ctfd_token_2,
                ctfd_token_3=settings.ctfd_token_3,
                ctfd_token_4=settings.ctfd_token_4,
            ),
            stable_secret=vault.secrets.master_secret,
        )

        # Rhythm settings for Token 1
        rhythm_settings = RhythmSettings.from_env()
        rhythm = ShiftRhythmEmitter(mqtt=mqtt, settings=rhythm_settings, secret=vault.secrets.master_secret)
        app.state.rhythm = rhythm
        await rhythm.start()

        # Setup alternative games
        games = CasinoGamesEmitter(mqtt=mqtt, seed=vault.secrets.master_secret, enable=True)
        app.state.games = games
        await games.start()

        # Setup Roulette and Regular Telemetry
        telemetry = CasinoTelemetry(mqtt, interval=1.0)
        app.state.telemetry = telemetry
        await telemetry.start()

        await _spawn_replayd(app)

        await mqtt.publish(
            "vault/status",
            {"ok": True, "heist": settings.heist_code},
            retain=True,
        )

        log.info("startup_complete")

    @app.on_event("shutdown")
    async def _shutdown():
        app.state.shutdown_in_progress = True
        try:
            proc = getattr(app.state, "replayd_proc", None)
            if proc and proc.returncode is None:
                proc.send_signal(signal.SIGTERM)
        except Exception:
            pass
        await db.close()

    app.include_router(router)
    # ------------------------------------------------------------------
    # Terminal compatibility routes (casino dashboard expects /terminal)
    # ------------------------------------------------------------------
    terminal = APIRouter(prefix="/terminal")

    from .routes import (
        ops_sync,
        ops_receipt_latest,
        api_state,
        fw_catalog,
        fw_upload,
    )

    terminal.add_api_route("/shift/sync", ops_sync, methods=["POST"])
    terminal.add_api_route("/receipts/latest", ops_receipt_latest, methods=["GET"])
    terminal.add_api_route("/state", api_state, methods=["GET"])
    terminal.add_api_route("/firmware/catalog", fw_catalog, methods=["GET"])
    terminal.add_api_route("/firmware/drop", fw_upload, methods=["POST"])

    app.include_router(terminal)

    return app

app = create_app()
