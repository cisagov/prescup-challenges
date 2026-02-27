from flask import Blueprint, jsonify, send_from_directory, abort
from pathlib import Path
from util.admin_gate import require_admin_session

ART_DIR = Path("/app/artifacts")
artifacts_bp = Blueprint("artifacts", __name__)

_DESCRIPTIONS = {
    "web_access.log": "Edge proxy access log - 2025-08-21",
    "dead_drop.zip": "Recovered operator dead-drop archive.",
    "mem.strings":   "Strings from short memory capture (XOR hint inside)",
    "opsec_fieldcard.txt": "OPSEC field card (metadata reminder)"
}

@artifacts_bp.get("/api/artifacts")
@require_admin_session
def list_artifacts():
    files = []
    names = ["web_access.log", "opsec_fieldcard.txt", "dead_drop.zip", "mem.strings"]
    # Expanded dead-drop set
    for name in names:
        p = ART_DIR / name
        if p.exists():
            try:
                sz = p.stat().st_size
            except Exception:
                sz = 0
            files.append({
                "file": name,
                "size": sz,
                "desc": _DESCRIPTIONS.get(name, "")
            })

    return jsonify({"artifacts": files})

    for name in names:
        p = ART_DIR / name
        if p.exists():
            try:
                sz = p.stat().st_size
            except Exception:
                sz = 0
            files.append({"file": name, "size": sz, "desc": _DESCRIPTIONS.get(name, "")})
    return jsonify({"artifacts": files})

@artifacts_bp.get("/artifacts/<path:filename>")
@require_admin_session
def get_artifact(filename: str):
    safe = {
        "web_access.log",
        "opsec_fieldcard.txt",
        "dead_drop.zip",
        "mem.strings",
    }

    if filename not in safe:
        abort(404)

    return send_from_directory(str(ART_DIR), filename, as_attachment=True)

