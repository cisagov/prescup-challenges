import os
import base64
import logging
from datetime import datetime, timedelta, timezone
import secrets
import sys

from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify
from flask_sqlalchemy import SQLAlchemy

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749.models import ClientMixin, TokenMixin
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant
from authlib.oauth2.rfc6749.models import AuthorizationCodeMixin
from authlib.oauth2.rfc7636 import CodeChallenge
from urllib.parse import urlparse

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

logging.basicConfig(
    level=logging.INFO,
    format=" %(asctime)s | [TIME_ANCHOR] | %(levelname)s | %(message)s",
)
logger = logging.getLogger("time_anchor")

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/anchor.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

ISSUER = "https://time_anchor.pre.pccc"
PARTNER_PASSWORD = os.environ.get("PARTNER_PASSWORD", "0HIca04GzISXUGiwVGMdwzoSi")

PARTNER_WATCH = os.environ.get("PARTNER_WATCH")
PLAYER_WATCH = os.environ.get("PLAYER_WATCH")

if PARTNER_WATCH is None or PLAYER_WATCH is None:
    logger.error("Missing required ENV var PARTNER_WATCH or PLAYER_WATCH")
    sys.exit(1)

# Space-separated redirect URIs (split on whitespace later, Authlib expects a list)
WATCH404_REDIRECT_URI = f"https://{PARTNER_WATCH}/callback https://{PARTNER_WATCH}/redirect"
WATCH127_REDIRECT_URI = f"https://{PLAYER_WATCH}/callback https://{PLAYER_WATCH}/redirect"

ALLOWED_DM_USERS = {"Agent404", "Agent127"}
DM_MAX = 100

# --- Keypair for JWT (generated at boot and kept in-process) ---
# For a CTF container this is fine; if you want persistence, store in sqlite or file.
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = RSA_KEY.public_key()
KID = "anchor-key-1"

def b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_from_public_key():
    numbers = PUB.public_numbers()
    return {
        "kty": "RSA",
        "kid": KID,
        "use": "sig",
        "alg": "RS256",
        "n": b64url_uint(numbers.n),
        "e": b64url_uint(numbers.e),
    }


# -----------------------------
# Models
# -----------------------------

class DMMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)


class Client(db.Model, ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, nullable=False)
    client_secret = db.Column(db.String(128), nullable=True)
    client_metadata = db.Column(db.Text, nullable=False, default="")

    @property
    def client_info(self):
        info = {}
        for line in (self.client_metadata or "").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k in ("redirect_uris", "grant_types", "response_types", "scope", "token_endpoint_auth_method"):
                info[k] = v.split()
            else:
                info[k] = v
        return info

    def check_redirect_uri(self, redirect_uri):
        ru = urlparse(redirect_uri)
        candidate = f"{ru.scheme}://{ru.netloc}{ru.path}"
        allowed = set(self.client_info.get("redirect_uris") or [])
        ok = candidate in allowed
        if not ok:
            logger.warning(
                "Redirect URI rejected: client_id=%s candidate=%s allowed=%s",
                self.client_id,
                candidate,
                sorted(allowed),
            )
        return ok

    def check_response_type(self, response_type):
        allowed = set(self.client_info.get("response_types") or [])
        return response_type in allowed

    def check_grant_type(self, grant_type):
        allowed = set(self.client_info.get("grant_types") or [])
        return grant_type in allowed

    def check_client_secret(self, client_secret):
        if self.client_secret is None:
            return client_secret in (None, "",)
        return self.client_secret == client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        allowed = set(self.client_info.get(
            "token_endpoint_auth_method") or ["client_secret_post"])
        return method in allowed

    def get_allowed_scope(self, scope):
        allowed = set((self.client_info.get("scope") or []))
        requested = set(scope.split()) if scope else set()
        return " ".join(sorted(requested & allowed))


class AuthorizationCode(db.Model, AuthorizationCodeMixin):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(120), unique=True, nullable=False)

    client_id = db.Column(db.String(64), db.ForeignKey(
        "client.client_id"), nullable=False)
    redirect_uri = db.Column(db.Text, nullable=False)
    scope = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # PKCE fields (we’ll keep them for later; required=True for now)
    code_challenge = db.Column(db.String(256), nullable=True)
    code_challenge_method = db.Column(db.String(16), nullable=True)

    created_at = db.Column(db.DateTime(
        timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    user = db.relationship("User")

    def is_expired(self):
        return datetime.now(timezone.utc) > (self.created_at.replace(tzinfo=timezone.utc) + timedelta(minutes=5))

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope


class Token(db.Model, TokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, nullable=True)

    token_type = db.Column(db.String(40), nullable=False, default="Bearer")
    access_token = db.Column(db.Text, unique=True, nullable=False)
    scope = db.Column(db.Text, nullable=True)

    issued_at = db.Column(db.Integer, nullable=False)
    expires_in = db.Column(db.Integer, nullable=False)

    def is_expired(self):
        return int(datetime.now(timezone.utc).timestamp()) > (self.issued_at + self.expires_in)


# -----------------------------
# OAuth glue
# -----------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)


def query_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


def issue_jwt_access_token(client_id: str, user: User, scope: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "sub": str(user.id),
        "aud": "time_device",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
        "scope": scope or "",
        "client_id": client_id,
        "username": user.username,
    }
    return jwt.encode(payload, RSA_KEY, algorithm="RS256", headers={"kid": KID})


def save_token(token_data, request_):
    # Override access_token with our JWT
    user = getattr(request_, "user", None)
    token_data["access_token"] = issue_jwt_access_token(
        request_.client.client_id, user, token_data.get("scope", ""))

    tok = Token(
        client_id=request_.client.client_id,
        user_id=user.id if user else None,
        access_token=token_data["access_token"],
        scope=token_data.get("scope"),
        issued_at=int(datetime.now(timezone.utc).timestamp()),
        expires_in=int(token_data.get("expires_in", 900)),
        token_type="Bearer",
    )
    db.session.add(tok)
    db.session.commit()
    
    logger.info(
        "Issued access token: client_id=%s user=%s scope=%s aud=%s exp=%s",
        request_.client.client_id,
        user.username if user else None,
        token_data.get("scope"),
        "time_device",
        token_data.get("expires_in"),
    )

    return tok


authorization_server = AuthorizationServer(
    app, query_client=query_client, save_token=save_token)


class MyAuthorizationCodeGrant(AuthorizationCodeGrant):
    # Allow public clients (watch has no secret)
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request_):
        auth_code = AuthorizationCode(
            code=code,
            client_id=request_.client.client_id,
            redirect_uri=request_.redirect_uri,
            scope=request_.scope,
            user_id=request_.user.id,
            code_challenge=request_.data.get("code_challenge"),
            code_challenge_method=request_.data.get("code_challenge_method"),
        )
        logger.info(
            "Issued code=%s user=%s pkce=%s method=%s",
            code, request_.user.username,
            bool(request_.data.get("code_challenge")),
            request_.data.get("code_challenge_method"),
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if item and item.is_expired():
            return None
        return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return authorization_code.user

    def get_authorization_code_challenge(self, authorization_code):
        return authorization_code.code_challenge

    def get_authorization_code_challenge_method(self, authorization_code):
        return authorization_code.code_challenge_method


def configure_oauth():
    # Normal operation: require PKCE (we’ll flip later for the vuln)
    authorization_server.register_grant(MyAuthorizationCodeGrant, [
                                        CodeChallenge(required=False)])

def bearer_claims():
    """
    Returns decoded JWT claims if a valid Bearer token is present, else None.
    """
    authz = request.headers.get("Authorization", "")
    if not authz.lower().startswith("bearer "):
        return None
    tok = authz.split(None, 1)[1].strip()
    if not tok:
        return None

    # Optional but realistic: ensure the token was actually issued by us
    # (prevents completely forged-but-valid-sig tokens if you ever rotate keys oddly).
    # If you don't want this, you can remove this check.
    db_tok = Token.query.filter_by(access_token=tok).first()
    if not db_tok or db_tok.is_expired():
        return None

    try:
        return jwt.decode(
            tok,
            PUB,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False},
        )
    except Exception as e:
        logger.warning("Bearer token rejected: %s", e)
        return None


def bearer_user(required_scope: str | None = None):
    """
    Returns (user, claims) if valid, else (None, None).
    """
    claims = bearer_claims()
    if not claims:
        return None, None

    if required_scope:
        scopes = set((claims.get("scope") or "").split())
        if required_scope not in scopes:
            return None, None

    username = claims.get("username")
    if not username:
        return None, None

    u = User.query.filter_by(username=username).first()
    return u, claims


# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def home():
    u = current_user()
    return render_template_string(
        """
        <h1>time_anchor (OAuth)</h1>
        {% if u %}
          <p>Logged in as <b>{{u.username}}</b></p>
          <p><a href="{{url_for('logout')}}">logout</a></p>
        {% else %}
          <p><a href="{{url_for('login')}}">login</a></p>
        {% endif %}
        <p><a href="/jwks.json">jwks.json</a></p>
        """,
        u=u,
    )

@app.get("/jwks.json")
def jwks():
    return jsonify({"keys": [jwk_from_public_key()]})


@app.get("/login")
@app.post("/login")
def login():
    if request.method == "GET":
        return render_template_string(
            """
            <h1>Login (time_anchor)</h1>
            <form method="post">
              <label>username <input name="username" value="Agent127"/></label><br/>
              <label>password <input name="password" value="password"/></label><br/>
              <input type="hidden" name="next" value="{{ request.args.get('next','') }}">
              <button type="submit">Login</button>
            </form>
            """,
        )

    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    user = User.query.filter_by(username=username, password=password).first()
    if not user:
        return "invalid credentials", 403

    session["uid"] = user.id

    nxt = request.args.get("next") or request.form.get("next")
    if nxt:
        logger.info("Login redirect candidate: %s", nxt)
        p = urlparse(nxt)

        # 1) Allow local absolute paths
        if p.scheme == "" and p.netloc == "" and p.path.startswith("/oauth/authorize"):
            return redirect(nxt)

        # 2) Allow absolute URLs only if they point back to *this* time_anchor host
        if p.scheme in ("http", "https") and p.netloc:
            # request.host is host[:port] for the current request
            if p.netloc == request.host and p.path.startswith("/"):
                return redirect(nxt)

    logger.info("Login redirect blocked (falling back): %s", nxt)
    return redirect(url_for("home"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    u = current_user()
    if not u:
        # preserve original authorize URL so login can resume the flow
        return redirect(url_for("login", next=request.url))

    logger.info(
        "Authorize request: client_id=%s user=%s redirect_uri=%s scope=%s",
        request.args.get("client_id"),
        u.username if u else None,
        request.args.get("redirect_uri"),
        request.args.get("scope"),
    )

    if request.method == "GET":
        grant = authorization_server.get_consent_grant(end_user=u)

        ALLOWED_USER_FOR_CLIENT = {
            "watch127": {"Agent127"},
            "watch404": {"Agent404"},   # or {"Agent404"} if you add that user
        }

        # inside authorize(), after `u = current_user()` and after you compute `grant`
        cid = grant.client.client_id
        allowed = ALLOWED_USER_FOR_CLIENT.get(cid)
        if allowed and u.username not in allowed:
            return "wrong watch", 403

        # AUTO-APPROVE for first-party watch client
        if grant.client.client_id in ("watch404", "watch127"):
            return authorization_server.create_authorization_response(grant_user=u)

        return render_template_string(
            """
            <h1>Authorize</h1>
            <p>User: <b>{{u.username}}</b></p>
            <p>Client: <b>{{grant.client.client_id}}</b></p>
            <p>Redirect: <code>{{grant.request.redirect_uri}}</code></p>
            <p>Scope: <b>{{grant.request.scope}}</b></p>
            <form method="post">
              <button name="confirm" value="yes" type="submit">Approve</button>
              <button name="confirm" value="no" type="submit">Deny</button>
            </form>
            """,
            u=u,
            grant=grant,
        )

    if request.form.get("confirm") != "yes":
        return authorization_server.create_authorization_response(grant_user=None)

    return authorization_server.create_authorization_response(grant_user=u)


@app.post("/oauth/token")
def token():
    return authorization_server.create_token_response()

@app.get("/dm")
def dm():
    u, claims = bearer_user(required_scope="chat")
    if not u:
        return "Unauthenticated credentials", 403

    if u.username not in ALLOWED_DM_USERS:
        return jsonify({"error": "invalid username"}), 400

    msgs = (
        DMMessage.query
        .order_by(DMMessage.id.asc())
        .all()
    )
    logger.info("DM fetch: user=%s count=%d", u.username, len(msgs))
    return jsonify([
        {"username": m.username, "message": m.message,
            "ts": m.created_at.isoformat() + "Z"}
        for m in msgs
    ])


@app.post("/send_dm")
def send_dm():
    u, claims = bearer_user(required_scope="chat")
    if not u:
        return "Unauthenticated credentials", 403

    data = request.get_json(silent=True) or {}
    username = u.username
    message = (data.get("message") or "").strip()

    if username not in ALLOWED_DM_USERS:
        return jsonify({"error": "invalid username"}), 400
    if not message:
        return jsonify({"error": "missing message"}), 400

    db.session.add(DMMessage(username=username, message=message))
    db.session.commit()
    logger.info("DM sent: from=%s len=%d", username, len(message))

    # Cap at 100 messages (delete oldest)
    count = DMMessage.query.count()
    if count > DM_MAX:
        overflow = count - DM_MAX
        oldest = (
            DMMessage.query
            .order_by(DMMessage.id.asc())
            .limit(overflow)
            .all()
        )
        for m in oldest:
            db.session.delete(m)
        db.session.commit()

    return jsonify({"ok": True})


# -----------------------------
# Init
# -----------------------------
def seed_dm_messages():
    if DMMessage.query.count() > 0:
        return  # don’t reseed if messages already exist

    db.session.add_all([
        DMMessage(
            username="Agent127",
            message="Does it feel like we are being... watched?"
        ),
        DMMessage(
            username="Agent127",
            message="Shhh! Seriously, DM me"
        ),
        DMMessage(
            username="Agent404",
            message="You're being paranoid. We are in the middle of nowhere, in the middle of no*when*."
        ),
        DMMessage(
            username="Agent127",
            message="I got away. You ok? Where are you?"
        ),
        DMMessage(
            username="Agent404",
            message="Hurt. Being dragged."
        ),
        DMMessage(
            username="Agent404",
            message="in camp"
        ),
        DMMessage(
            username="Agent404",
            message="fire"
        ),
        DMMessage(
            username="Agent404",
            message="fire for me!!1!"
        ),
        DMMessage(
            username="Agent127",
            message="Emergency extract has been approved, get out of there."
        ),
        DMMessage(
            username="Agent404",
            message="something wro"
        ),
        DMMessage(
            username="Agent404",
            message="[pl,km"
        ),
    ])
    db.session.commit()


def upsert_client(client_id: str, redirect_uris: str):
    md = "\n".join(
        [
            f"redirect_uris={redirect_uris}",
            "grant_types=authorization_code",
            "response_types=code",
            "scope=device.control chat telemetry.read",
            "token_endpoint_auth_method=none",
        ]
    )

    c = Client.query.filter_by(client_id=client_id).first()
    if c:
        c.client_secret = None
        c.client_metadata = md
    else:
        db.session.add(Client(client_id=client_id,
                       client_secret=None, client_metadata=md))


def seed():
    # Users:
    if not User.query.filter_by(username="Agent127").first():
        db.session.add(User(username="Agent127", password="password"))
    if not User.query.filter_by(username="Agent404").first():
        db.session.add(User(username="Agent404", password=PARTNER_PASSWORD))

    # Clients: always upsert so hostname changes take effect
    upsert_client("watch404", WATCH404_REDIRECT_URI)
    upsert_client("watch127", WATCH127_REDIRECT_URI)

    db.session.commit()
    logger.info("Seeded users and watch clients")


with app.app_context():
    db.create_all()
    seed()
    seed_dm_messages()
    configure_oauth()
