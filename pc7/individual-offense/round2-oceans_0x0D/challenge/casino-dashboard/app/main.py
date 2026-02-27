from __future__ import annotations
import asyncio, logging, time
import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .config import load_settings
from .logging_setup import setup_logging
from .state_cache import DashboardState
from .ws_hub import WebSocketHub
from .routes import router

log = logging.getLogger("dash")

def create_app() -> FastAPI:
    settings = load_settings()
    setup_logging(settings.log_level, settings.log_json)

    app = FastAPI(title="Casino Dashboard", version="4.0.0", docs_url=None, redoc_url=None, openapi_url=None)

    state = DashboardState()
    state.events = state.events.__class__(maxlen=settings.ui_event_buffer)
    hub = WebSocketHub()

    app.state.settings = settings
    app.state.state = state
    app.state.hub = hub

    app.mount("/static", StaticFiles(directory="/app/web", html=False), name="static")

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard():
        with open("/app/web/dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())

    app.include_router(router)

    @app.on_event("startup")
    async def _startup():
        app.state.poll_task = asyncio.create_task(_poll_vault_loop(app))
        log.info("startup_complete", extra={"vault_core_url": settings.vault_core_url})

    async def _poll_vault_loop(app: FastAPI):
        settings = app.state.settings
        state: DashboardState = app.state.state
        hub: WebSocketHub = app.state.hub
        poll_s = max(0.2, settings.ui_poll_fallback_ms / 1000.0)

        async with httpx.AsyncClient(timeout=2.8) as client:
            while True:
                await asyncio.sleep(poll_s)
                try:
                    r = await client.get(f"{settings.vault_core_url}/api/state")
                    data = r.json()
                    state.degraded = False
                except Exception:
                    state.degraded = True
                    await hub.broadcast({"type":"STATE","data": state.as_public()})
                    continue

                alert = data.get("alert", {})
                tokens = data.get("tokens", {})

                state.alert_level = int(alert.get("level", 0))
                state.alert_state = alert.get("state", "NORMAL")
                state.alert_score = float(alert.get("score", 0.0))
                state.lockdown_until = int(alert.get("lockdown_until", 0))

                # Helper: transition handler
                async def on_found(token_idx: int, label: str, slip_path: str, reveal_seconds: int):
                    try:
                        rr = await client.get(f"{settings.vault_core_url}{slip_path}")
                        rec = rr.json()
                        # token1 uses receipt format: {"token": "..."}
                        if token_idx == 1:
                            tok = rec.get("token", "")
                            terminal = "CAGE-TERMINAL"
                        else:
                            tok = rec.get("auth", "")
                            terminal = rec.get("terminal")

                        if tok:
                            setattr(state, f"token{token_idx}_value", tok)
                            setattr(state, f"token{token_idx}_reveal_until", int(time.time()) + reveal_seconds)
                            state.events.appendleft({
                                "ts": int(time.time()),
                                "type": "SLIP_PRINTED",
                                "token": token_idx,
                                "terminal": terminal
                            })

                    except Exception:
                        state.events.appendleft({"ts": int(time.time()), "type": "SLIP_BLOCKED", "token": token_idx, "msg": "SOC interception suspected"})

                # Token 1
                prev = state.token1_found
                t = tokens.get("token1", {})
                state.token1_found = bool(t.get("found", False))
                state.token1_found_at = int(t.get("found_at", 0))
                if state.token1_found and not prev:
                    state.events.appendleft({"ts": int(time.time()), "type":"TOKEN_FOUND", "token":1, "label":"HOUSE RHYTHM"})
                    try: 
                        await on_found(1, "HOUSE RHYTHM", "/api/ops/receipt/latest", settings.ui_blueiprint_reveal_seconds)
                    # state.token1_value = dispenser.token1()
                    # state.token1_reveal_until = int(time.time()) + settings.ui_blueprint_reveal_seconds
                    except Exception:
                        pass

                # If the token is found but the slip couldn't be printed yet (e.g., alert/lockdown),
                # retry on subsequent polls until we successfully fetch it once.
                if state.token1_found and not state.token1_value:
                    try:
                        await on_found(1, "HOUSE RHYTHM", "/api/ops/receipt/latest", settings.ui_blueprint_reveal_seconds)
                    except Exception:
                        pass

                # Token 2
                prev = state.token2_found
                t = tokens.get("token2", {})
                state.token2_found = bool(t.get("found", False))
                state.token2_found_at = int(t.get("found_at", 0))
                if state.token2_found and not prev:
                    state.events.appendleft({"ts": int(time.time()), "type":"TOKEN_FOUND", "token":2, "label":"BURNED BLUEPRINT"})
                    try: 
                        await on_found(2, "BURNED BLUEPRINT", "/api/ops/maintenance/blueprint-slip", settings.ui_blueprint_reveal_seconds)
                    # state.token2_value = dispenser.token1()
                    # state.token2_reveal_until = int(time.time()) + settings.ui_blueprint_reveal_seconds
                    except Exception:
                        pass


                # If the token is found but the slip couldn't be printed yet (e.g., alert/lockdown),
                # retry on subsequent polls until we successfully fetch it once.
                if state.token2_found and not state.token2_value:
                    await on_found(2, "BURNED BLUEPRINT", "/api/ops/maintenance/blueprint-slip", settings.ui_blueprint_reveal_seconds)

                # Token 3
                prev = state.token3_found
                t = tokens.get("token3", {})
                state.token3_found = bool(t.get("found", False))
                state.token3_found_at = int(t.get("found_at", 0))
                if state.token3_found and not prev:
                    state.events.appendleft({"ts": int(time.time()), "type":"TOKEN_FOUND", "token":3, "label":"GHOST IN THE STACK"})
                    await on_found(3, "GHOST IN THE STACK", "/api/ops/maintenance/ghost-slip", settings.ui_ghost_reveal_seconds)

                # If the token is found but the slip couldn't be printed yet (e.g., alert/lockdown),
                # retry on subsequent polls until we successfully fetch it once.
                if state.token3_found and not state.token3_value:
                    await on_found(3, "GHOST IN THE STACK", "/api/ops/maintenance/ghost-slip", settings.ui_ghost_reveal_seconds)

                # Token 4
                prev = state.token4_found
                t = tokens.get("token4", {})
                state.token4_found = bool(t.get("found", False))
                state.token4_found_at = int(t.get("found_at", 0))
                if state.token4_found and not prev:
                    state.events.appendleft({"ts": int(time.time()), "type":"TOKEN_FOUND", "token":4, "label":"FALSE FLOOR"})
                    await on_found(4, "FALSE FLOOR", "/api/ops/maintenance/floor-slip", settings.ui_falsefloor_reveal_seconds)

                # If the token is found but the slip couldn't be printed yet (e.g., alert/lockdown),
                # retry on subsequent polls until we successfully fetch it once.
                if state.token4_found and not state.token4_value:
                    await on_found(4, "FALSE FLOOR", "/api/ops/maintenance/floor-slip", settings.ui_falsefloor_reveal_seconds)

                await hub.broadcast({"type":"STATE","data": state.as_public()})

    return app

app = create_app()
