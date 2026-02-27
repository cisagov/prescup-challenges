from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# CORS: allow the custom admin header and /artifacts
CORS(
    app,
    resources={
        r"/api/*": {"origins": "*"},
        r"/portal/*": {"origins": "*"},
        r"/artifacts/*": {"origins": "*"},
    },
    allow_headers=["Content-Type", "Ops-Session", "X-Admin-Session"],
)

# Seed forensic artifacts on startup (Tokens 2–4)
from util.init_artifacts import ensure_artifacts
ensure_artifacts()

# Register all blueprints
from endpoints.auth import auth_bp
from endpoints.dashboard import dashboard_bp
from endpoints.incident import incident_bp
from endpoints.docs import docs_bp
from endpoints.notes import notes_bp
from endpoints.session import session_bp
from endpoints.feedback import feedback_bp
from endpoints.admin import admin_bp
from endpoints.artifacts import artifacts_bp

for bp in (
    auth_bp,
    dashboard_bp,
    incident_bp,
    docs_bp,
    notes_bp,
    session_bp,
    feedback_bp,
    admin_bp,
    artifacts_bp,
):
    app.register_blueprint(bp)

@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "safehouse-backend"
    }, 200

@app.get("/api")
def api_root():
    # simple, unauthenticated “alive” response to match guide expectations
    return {"ok": True}, 200

@app.get("/portal")
def portal_root():
    # redirect to the real admin door (or whatever your portal entry is)
    return "", 302, {"Location": "/portal/admin-entry"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


