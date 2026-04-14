from __future__ import annotations

from pathlib import Path
import logging
import json
from urllib.parse import urlparse, urlunparse

import httpx
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Request, UploadFile, File
from fastapi.responses import HTMLResponse, Response

from .state_cache import DashboardState
from .ws_hub import WebSocketHub

log = logging.getLogger("dash.terminal")

router = APIRouter()
WEB_DIR = Path(__file__).resolve().parents[1] / "web"


def get_state(request: Request) -> DashboardState:
    return request.app.state.state

def get_state_ws(ws: WebSocket) -> DashboardState:
    return ws.app.state.state

def get_hub(ws: WebSocket):
    return ws.app.state.hub

def _vaultcore_base(request: Request) -> str:
    # Use the dashboard settings object (single source of truth)
    settings = request.app.state.settings
    return str(settings.vault_core_url).rstrip("/")


def _swap_host(url: str) -> str:
    """
    Fallback: some platforms only resolve *.pccc names, others resolve Docker service names.
    If host is 'vaultcore' -> try 'vaultcore.pccc'
    If host is 'vaultcore.pccc' -> try 'vaultcore'
    Otherwise return original.
    """
    p = urlparse(url)
    host = p.hostname or ""
    if host == "vaultcore":
        new_host = "vaultcore.pccc"
    elif host == "vaultcore.pccc":
        new_host = "vaultcore"
    else:
        return url

    netloc = new_host
    if p.port:
        netloc = f"{new_host}:{p.port}"
    return urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))


def _jsonish(content: bytes) -> bytes:
    return content if content else b"{}"


async def _proxy(
    request: Request,
    method: str,
    path: str,
    *,
    json_body=None,
    files=None,
    timeout_s: float = 10.0,
    passthrough_headers: tuple[str, ...] = ("content-type", "content-disposition"),
) -> Response:
    base = _vaultcore_base(request)
    url = f"{base}{path}"
    alt_url = f"{_swap_host(base)}{path}"

    last_err = None
    for attempt, target in enumerate((url, alt_url), start=1):
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                r = await client.request(method, target, json=json_body, files=files)
                headers = {k: r.headers[k] for k in passthrough_headers if k in r.headers}
                return Response(
                    content=_jsonish(r.content) if "application/json" in r.headers.get("content-type", "") else r.content,
                    status_code=r.status_code,
                    headers=headers,
                    media_type=r.headers.get("content-type", "application/json"),
                )
        except Exception as e:
            last_err = e
            log.warning("vaultcore_proxy_failed", extra={"attempt": attempt, "url": target, "err": str(e)})

    # Both attempts failed: return a structured 502 for the UI
    return Response(
        content=_jsonish(
            f'{{"ok":false,"err":"vaultcore_unreachable","detail":{json.dumps(str(last_err))},"tried":["{url}","{alt_url}"]}}'.encode()
        ),
        status_code=502,
        media_type="application/json",
    )


@router.get("/healthz")
async def healthz():
    return {"ok": True}


@router.get("/api/public")
async def api_public(state: DashboardState = Depends(get_state)):
    return state.as_public()


@router.get("/terminal", response_class=HTMLResponse)
async def terminal_page():
    return (WEB_DIR / "ops.html").read_text(encoding="utf-8")


@router.get("/terminal/incidents/download")
async def download_incidents(state: DashboardState = Depends(get_state)):
    return Response(
        content=json.dumps(list(state.incidents), indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=incident-log.json"
        },
    )


@router.get("/", response_class=HTMLResponse)
async def root_page():
    return (WEB_DIR / "dashboard.html").read_text(encoding="utf-8")


@router.get("/terminal/state")
async def terminal_state(request: Request):
    return await _proxy(request, "GET", "/api/state", timeout_s=5.0)


@router.post("/terminal/shift/sync")
async def terminal_shift_sync(request: Request):
    body = await request.json()
    return await _proxy(request, "POST", "/api/ops/sync", json_body=body, timeout_s=15.0)


@router.get("/terminal/receipts/latest")
async def terminal_receipts_latest(request: Request):
    return await _proxy(request, "GET", "/api/ops/receipt/latest", timeout_s=5.0)


@router.get("/terminal/firmware/catalog")
async def terminal_fw_catalog(request: Request):
    return await _proxy(request, "GET", "/api/fw/catalog", timeout_s=5.0)


@router.get("/terminal/firmware/download/{release_id}")
async def terminal_fw_download(request: Request, release_id: str):
    # keep binary headers
    return await _proxy(
        request,
        "GET",
        f"/api/fw/download/{release_id}",
        timeout_s=25.0,
        passthrough_headers=("content-type", "content-disposition"),
    )


@router.post("/terminal/firmware/drop")
async def terminal_fw_upload(request: Request, file: UploadFile = File(...)):
    data = await file.read()
    files = {"file": (file.filename, data, file.content_type or "application/octet-stream")}
    return await _proxy(request, "POST", "/api/fw/upload", files=files, timeout_s=35.0)


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket, hub: WebSocketHub = Depends(get_hub), state: DashboardState = Depends(get_state_ws)):
    await hub.connect(ws)
    try:
        await ws.send_json({"type": "STATE", "data": state.as_public()})
        while True:
            _ = await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(ws)
