# logger-node/app/main.py
from fastapi import FastAPI, Request, Header, Body, Response
from fastapi.responses import PlainTextResponse, FileResponse, JSONResponse
from typing import Dict, Deque
from collections import deque
import os, base64, hmac, hashlib, time, threading

app = FastAPI()

# Paths
BASE_DIR = '/app'
CERT_DIR = os.path.join(BASE_DIR, 'certs')
DATA_DIR = os.path.join(BASE_DIR, 'data')
nonce = base64.b64encode(os.urandom(8)).decode('ascii')
fragment_a = 'ag'
fragment_b = 'ent_key_B'

# --- Lightweight rate limiting for /validate (anti-bruteforce, reduces tickets) ---
RATE_WINDOW_SECONDS = 60      # sliding window
RATE_MAX_REQUESTS = 30        # per window, per client
_auth_hits: Dict[str, Deque[float]] = {}

def _client_id(request: Request) -> str:
    # Prefer X-Forwarded-For if present (behind reverse proxy), else client host
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")

def _rate_limited(request: Request) -> bool:
    now = time.time()
    cid = _client_id(request)
    q = _auth_hits.setdefault(cid, deque())
    # prune old
    while q and (now - q[0] > RATE_WINDOW_SECONDS):
        q.popleft()
    if len(q) >= RATE_MAX_REQUESTS:
        return True
    q.append(now)
    return False

_nonce_lock = threading.Lock()
_current_nonce: str | None = None

def _new_nonce() -> str:
    return base64.b64encode(os.urandom(8)).decode("ascii")

def get_nonce(refresh: bool = False) -> str:
    global _current_nonce
    with _nonce_lock:
        if refresh or _current_nonce is None:
            _current_nonce = _new_nonce()
        return _current_nonce


# --- Discovery breadcrumbs (fair, non-spoiler) ---
@app.get("/robots.txt")
def robots():
    body = "User-agent: *\nDisallow: /admin/\nSitemap: /sitemap.xml\n"
    return PlainTextResponse(body, media_type="text/plain; charset=utf-8")

@app.get("/sitemap.xml")
def sitemap():
    # List helpful-but-not-spoiler endpoints. Do NOT list /logs or /artifacts directly.
    body = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/alter_log</loc></url>
  <url><loc>/health</loc></url>
  <url><loc>/meta</loc></url>
  <url><loc>/errors</loc></url>
  <url><loc>/validate</loc></url>
  <url><loc>/.well-known/logger</loc></url>
</urlset>
"""
    return PlainTextResponse(body, media_type="application/xml; charset=utf-8")

@app.get("/.well-known/logger")
def well_known_logger():
    # Gentle nudge toward standard ops endpoints (no spoilers)
    return JSONResponse({"hint": "This host exposes health, meta and errors endpoints for operations. Debug views may require specific headers."})

# --- Core endpoints (unchanged semantics; added helpful headers) ---
@app.get('/logs')
def logs(response: Response):
    """
    Return the textual logs that embed the PEM and reference the DER artifact.
    Adds Link and split X-Log-* headers as subtle breadcrumbs (fair discovery).
    """
    # Breadcrumbs that point to discovery endpoints, not directly to artifacts
    response.headers['Link'] = '</health>; rel="service", </meta>; rel="meta", </errors>; rel="error", </.well-known/logger>; rel="well-known"'
    # Split hint that suggests existence of artifacts path without filename
    response.headers['X-Log-1'] = '/art'
    response.headers['X-Log-2'] = 'ifacts/'
    p = os.path.join(DATA_DIR, 'logs.txt')
    return PlainTextResponse(open(p, 'rb').read(), headers=response.headers)

@app.get('/artifacts/event_certificate.der')
def event_der():
    path = os.path.join(CERT_DIR, 'event_certificate.der')
    return FileResponse(path, media_type='application/octet-stream')

@app.get('/health')
def health(request: Request, response: Response):
    """
    Minimal health check.
    - Always returns a default payload.
    - If client sends X-Debug: yes (case-insensitive), leak a small extra fragment.
    - Always sets an X-Debug header in the response (default 'no', 'yes' when enabled).
    """
    # Default data
    data = {
        'status': 'ok',
        'services': {
            'db': 'db:5432',
            'auth': 'auth.embassy.svc'
        }
    }

    # Normalize the incoming header value (handle 'yes', 'Yes', etc.)
    incoming_debug = request.headers.get('X-Debug', '').lower().strip()

    if incoming_debug == 'yes':
        # add the leaked fragment
        data['services']['cfg_fragment_a'] = 'ag'
        # safely add a session value
        data['session'] = {'value': 'CgWv87vQDPrsrPHVu6'}
        # mark response header
        response.headers['X-Debug'] = 'yes'
    else:
        # ensure header is always present and defaults to 'no'
        response.headers['X-Debug'] = 'no'

    return JSONResponse(data, headers=response.headers)


@app.get("/alter_log")
def alter_log(request: Request, response: Response):
    """
    - If X-Debug: yes -> rotate nonce and include helpful, non-spoiler hints.
    - Otherwise -> keep current nonce and mark debug off.
    - Always reflect X-Debug in response headers.
    """
    incoming_debug = (request.headers.get("X-Debug", "") or "").strip().lower()
    debug_on = incoming_debug == "yes"

    if debug_on:
        # rotate nonce to prevent replay across tiers
        nonce = get_nonce(refresh=True)
        response.headers["X-Debug"] = "yes"

        payload = {
            "nonce": nonce,
            "debug": {"status": "on"},
            "help": {
                # clear, consistent guidance for the next step
                "message": (
                    "First-tier authorization: send header X-Agent containing "
                    "hex(HMAC_SHA256(agent_key, nonce)), and POST the same nonce to /validate."
                ),
                "header": "X-Agent",
                "hash": "HMAC_SHA256",
                "agent key": "fragments of the agent_key are scattered across various endpoints for security purposes."
            },
        }
        # Return JSON while preserving headers we set on the Response object
        return JSONResponse(payload, headers=dict(response.headers))
    else:
        # keep existing nonce (don’t rotate), and mark debug off
        nonce = get_nonce(refresh=False)
        response.headers["X-Debug"] = "no"
        return JSONResponse({"nonce": nonce, "debug": {"status": "off"}}, headers=dict(response.headers))

# HMAC handshake: client must send X-Agent = hex(HMAC_SHA256(agent_key, nonce))
@app.post('/validate')
async def agent_auth(request: Request, nonce: str = Body(...), x_agent: str = Header(None)):
    global fragment_a, fragment_b
    # Simple per-client rate limit to prevent brute forcing and reduce support tickets
    if _rate_limited(request):
        return JSONResponse({'error': 'rate_limited'}, status_code=429)

    # In the real event, solver reconstructs this from fragments; we mirror that composition.
    agent_key = fragment_a + fragment_b  # derived from /health (X-Debug) + /meta (session header)

    expected = hmac.new(agent_key.encode('utf-8'), nonce.encode('utf-8'), hashlib.sha256).hexdigest()
    if x_agent and hmac.compare_digest(expected, x_agent):
        # Return artifact filename as base64 (forces simple decode, avoids direct spoiler)
        filename = 'event_certificate.der'
        return JSONResponse(
            {"certificate": {
                "status": "validated",
                "location": "http://logger.embassy.svc:8080/artifacts/",
                "name": "event_certificate.der"
            }},
            status_code=200
        )
    return JSONResponse({'error': 'unauthorized'}, status_code=403)

@app.get('/admin')
def default_message():
    return JSONResponse({'message': 'Unauthorized. For Internal Use only.'}, status_code=503)


@app.get('/errors')
def errors():
    """
    Simulated stacktrace with broken base64 for the artifact name (fallback path).
    Deterministic by design to avoid tickets when handshake path is missed.
    """
    # 'event_certificate.der's name is discovered here
    block = 'open("/app/artifacts/Y2VydGlmaWNhdGUgbmFtZTogZXZlbnRfY2VydHJpZmljdF9jZXJ0aWZpY2F0ZS5kZXI=", "rb")'
    trace = (
        "Traceback (most recent call last):\n"
        "  File \"/app/logger/handler.py\", line 234, in save\n"
        f"    {block}\n"
        "FileNotFoundError: [Errno 2] No such file or directory. No access at this level."
    )
    return PlainTextResponse(trace)

@app.get('/meta')
def meta(session: str = Header(None)):
    """
    Return a base64 fragment when a weak session header is presented.
    Mirrors common 'oops we left a meta leak' scenarios in microservice stacks.
    """
    if session == 'CgWv87vQDPrsrPHVu6':
        # base64('ent_key_B') == 'ZW50X2tleV9C'
        return JSONResponse({'services': {'cfg_fragment_b': 'ZW50X2tleV9C'}})
    return JSONResponse({'msg': 'Missing session header or incorrect session value.'})
