import os
import base64
import hashlib
import secrets
import logging
import ssl
import sys
import time
import requests
from flask import Flask, Response, render_template, session, redirect, request, url_for, jsonify
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
import jwt
from functools import wraps
from jwt import PyJWKClient

logging.basicConfig(
    level=logging.INFO,
    format=" %(asctime)s | [WATCH] | %(levelname)s | %(message)s",
)
logger = logging.getLogger("watch")

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

TIME_ANCHOR_BASE = "https://time_anchor.pre.pccc"
TIME_DEVICE_BASE = "https://time_device.pre.pccc"

AGENT_ID = os.environ.get("AGENT_ID")

if AGENT_ID is None:
    logger.error("Missing required ENV var AGENT_ID")
    sys.exit(1)

HOST = os.environ.get("HOST")

if HOST is None:
    logger.error("Missing required ENV var HOST")
    sys.exit(1)

WATCH_URL = f"https://{HOST}"

CLIENT_ID = os.environ.get("CLIENT_ID")

if CLIENT_ID is None:
    logger.error("Missing required ENV var CLIENT_ID")
    sys.exit(1)

DEVICE_SCOPE = "device.control"
CHAT_SCOPE = "chat"

SCOPE_TO_TOKEN_KEY = {
    DEVICE_SCOPE: "access_token_device",
    CHAT_SCOPE: "access_token_chat",
}

JWKS_URL = "https://time_anchor.pre.pccc/jwks.json"

ssl_context = ssl.create_default_context(cafile="/etc/ssl/certs/ca-certificates.crt")
_jwks_client = PyJWKClient(JWKS_URL, ssl_context=ssl_context)

def verify_token(token: str):
    signing_key = _jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(token, signing_key.key, algorithms=["RS256"], issuer=TIME_ANCHOR_BASE, options={"verify_aud": False})

def require_oauth(scope: str):
    def deco(fn):
        @wraps(fn)
        def wrap(*args, **kwargs):
            logger.info(
                "require_oauth enter path=%s method=%s scope_required=%s agent_id=%s",
                request.path,
                request.method,
                scope,
                AGENT_ID,
            )

            token_key = SCOPE_TO_TOKEN_KEY.get(scope, "access_token")
            logger.info("require_oauth token_key=%s session_has_token=%s", token_key, token_key in session)

            tok = session.get(token_key)
            if not tok:
                logger.info(
                    "require_oauth missing_token token_key=%s -> redirect /start scope=%s next=%s",
                    token_key,
                    scope,
                    request.full_path,
                )
                return redirect(url_for("start", scope=scope, next=request.full_path))

            logger.info(
                "require_oauth found_token token_key=%s token_len=%s", token_key, len(tok) if isinstance(tok, str) else -1,)

            try:
                claims = verify_token(tok)
                logger.info(
                    "require_oauth token_verified token_key=%s username=%s scope_claim=%s exp=%s iat=%s aud=%s iss=%s",
                    token_key,
                    claims.get("username"),
                    claims.get("scope"),
                    claims.get("exp"),
                    claims.get("iat"),
                    claims.get("aud"),
                    claims.get("iss"),
                )

                if claims.get("username") != AGENT_ID:
                    logger.warning(
                        "require_oauth wrong_user expected=%s got=%s -> clearing %s and 403",
                        AGENT_ID,
                        claims.get("username"),
                        token_key,
                    )
                    session.pop(token_key, None)
                    return "wrong user for this watch", 403

            except Exception as e:
                logger.exception(
                    "require_oauth verify_failed token_key=%s err=%r -> clearing and redirect /start scope=%s next=%s",
                    token_key,
                    e,
                    scope,
                    request.full_path,
                )
                session.pop(token_key, None)
                return redirect(url_for("start", scope=scope, next=request.full_path))

            scopes = set((claims.get("scope") or "").split())
            logger.info(
                "require_oauth scopes_parsed required=%s present=%s",
                scope,
                " ".join(sorted(scopes)) if scopes else "(none)",
            )

            if scope not in scopes:
                logger.info(
                    "require_oauth missing_scope required=%s present=%s -> redirect /start scope=%s next=%s",
                    scope,
                    " ".join(sorted(scopes)) if scopes else "(none)",
                    scope,
                    request.full_path,
                )
                # token exists but doesn't have the needed scope -> get the right grant
                return redirect(url_for("start", scope=scope, next=request.full_path))

            request.claims = claims
            logger.info(
                "require_oauth allow path=%s scope=%s token_key=%s",
                request.path,
                scope,
                token_key,
            )
            return fn(*args, **kwargs)

        return wrap

    return deco

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_pkce_pair():
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def fetch_messages(access_token: str | None):
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    logger.info("DM fetch outbound token_present=%s", bool(access_token))
    try:
        r = requests.get(f"{TIME_ANCHOR_BASE}/dm", verify="/etc/ssl/certs/ca-certificates.crt", headers=headers, timeout=5)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        logger.error("DM fetch failed http=%s body=%r", getattr(e.response, "status_code", None), (getattr(e.response, "text", "")[:200]))
        raise
    except Exception as e:
        logger.error("DM fetch failed: %s", e)
        raise

    
def send_message(access_token: str | None, message: str):
    headers = {"Content-Type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    payload = {"message": message}
    r = requests.post(f"{TIME_ANCHOR_BASE}/send_dm", verify="/etc/ssl/certs/ca-certificates.crt", json=payload, headers=headers, timeout=5)
    r.raise_for_status()
    return r.json()


@app.get("/")
def home():
    if CLIENT_ID == "watch127":
        coords="42.3729° N, 71.0551° E"
        image= 'imgs/kali.png'
    else:
        coords="42.3763° N, 71.0611° E"
        image= 'imgs/fire.png'
    
    return render_template("index.html", coords=coords, image=image)


@app.get("/dm")
@require_oauth(scope=CHAT_SCOPE)
def get_dms():
    tok = session.get("access_token_chat")
    if not tok:
        return redirect(url_for("home"))
    msgs = fetch_messages(tok)
    return render_template("chat.html", messages=msgs)

@app.get("/dm_api")
@require_oauth(scope=CHAT_SCOPE)
def get_dms_api():
    tok = session.get("access_token_chat")
    if not tok:
        return redirect(url_for("home"))
    msgs = fetch_messages(tok)
    return msgs


@app.post("/dm")
@require_oauth(scope=CHAT_SCOPE)
def post_dms():
    tok = session.get("access_token_chat")
    if not tok:
        return redirect(url_for("home"))
    message = (request.form.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Missing message"}), 400

    send_message(tok, message)
    msgs = fetch_messages(tok)
    return render_template("chat.html", messages=msgs)

@app.get("/start")
def start():
    scope = request.args.get("scope") or DEVICE_SCOPE
    token_key = SCOPE_TO_TOKEN_KEY.get(scope, "access_token")
    session["oauth_scope"] = scope
    session["oauth_token_key"] = token_key

    final_next = request.args.get("next") or "/"
    session["post_auth_next"] = final_next
    
    state = b64url(secrets.token_bytes(12))
    verifier, challenge = make_pkce_pair()

    session["oauth_state"] = state
    session["pkce_verifier"] = verifier

    # Use the open redirect as the OAuth redirect_uri; it will forward code/state to /callback
    # and keep our 'next' intact.
    redirect_uri = f"{WATCH_URL}/redirect?{urlencode({'next': f'{WATCH_URL}/callback?next={final_next}'})}"
    session["oauth_redirect_uri"] = redirect_uri

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    url = f"{TIME_ANCHOR_BASE}/oauth/authorize?{urlencode(params)}"
    return redirect(url)


@app.get("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state:
        return "missing code/state", 400
    if state != session.get("oauth_state"):
        return "bad state", 400

    # verifier = session.get("pkce_verifier")
    # if not verifier:
    #     return "missing pkce verifier", 400

    redirect_uri = session.get("oauth_redirect_uri") or f"{WATCH_URL}/callback"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": CLIENT_ID,
    }

    verifier = session.get("pkce_verifier")
    if verifier:
        data["code_verifier"] = verifier

    # self-signed TLS: verify=False for internal CTF network
    r = requests.post(f"{TIME_ANCHOR_BASE}/oauth/token", data=data, verify="/etc/ssl/certs/ca-certificates.crt", timeout=5)
    if r.status_code != 200:
        logger.error("token exchange failed %s: %s", r.status_code, r.text)
        return (f"token exchange failed: {r.status_code}\n{r.text}", 502)

    token = r.json()
    token_key = session.get("oauth_token_key", "access_token")
    session[token_key] = token.get("access_token")
    logger.info(f"Got {session[token_key]} in {token_key}")
    # optional bookkeeping
    session[token_key + "_scope"] = token.get("scope")
    nxt = request.args.get("next") or session.pop(
        "post_auth_next", None) or url_for("home")
    return redirect(nxt)


@app.get("/redirect")
def open_redirect():
    nxt = request.args.get("next", "")
    if not nxt:
        return "missing next", 400

    # Drop 'next' itself from forwarded params; forward the rest (code/state/etc.)
    params = [(k, v) for (k, v) in request.args.items() if k != "next"]

    u = urlparse(nxt)
    q = list(parse_qsl(u.query, keep_blank_values=True))
    q.extend(params)

    dest = urlunparse((u.scheme, u.netloc, u.path,
                      u.params, urlencode(q), u.fragment))
    return redirect(dest, code=302)


@app.get("/escape")
@require_oauth(DEVICE_SCOPE)
def escape():
    tok = session.get("access_token_device")
    if not tok:
        return redirect(url_for("home"))

    logger.info("Escape request outbound agent=%s", AGENT_ID)
    r = requests.post(f"{TIME_DEVICE_BASE}/escape", headers={"Authorization": f"Bearer {tok}"}, verify="/etc/ssl/certs/ca-certificates.crt", timeout=5)
    logger.info("Escape response status=%s body_len=%d", r.status_code, len(r.text))
    return (r.text, r.status_code, {"Content-Type": "application/json"})

CA_UPSTREAM = "http://ca.pre.pccc:8080/ca.crt"  # reachable from this proxy container

_CA_CACHE = {"ts": 0.0, "body": b""}
_CA_TTL_SECONDS = 60

@app.get("/ca.crt")
def proxy_ca_crt():
    now = time.time()
    if _CA_CACHE["body"] and (now - _CA_CACHE["ts"]) < _CA_TTL_SECONDS:
        return Response(_CA_CACHE["body"], mimetype="application/x-x509-ca-cert")

    r = requests.get(CA_UPSTREAM, timeout=3)
    r.raise_for_status()
    body = r.content
    if not body:
        return Response("upstream CA empty\n", status=502, mimetype="text/plain")

    _CA_CACHE["ts"] = now
    _CA_CACHE["body"] = body
    return Response(body, mimetype="application/x-x509-ca-cert")