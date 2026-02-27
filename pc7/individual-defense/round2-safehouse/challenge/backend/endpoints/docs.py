# backend/endpoints/docs.py
from __future__ import annotations

import mimetypes
import urllib.parse
from pathlib import Path

from flask import Blueprint, jsonify, request, send_file
from util.admin_gate import require_admin_session

docs_bp = Blueprint("docs", __name__)

# Serve ONLY from this directory
DOCS_DIR = Path("/app/docs")
DOCS_DIR.mkdir(parents=True, exist_ok=True)

# Keep it tight
ALLOWED_SUFFIXES = {".pdf", ".txt", ".md"}
MAX_PATH_LEN = 200  # sanity limit on input length


def _first_param(*names: str) -> str | None:
    for n in names:
        v = request.args.get(n)
        if v:
            return v
    return None


def _safe_resolve(base: Path, user_input: str) -> Path | None:
    """
    Strictly resolve a user-supplied path to a safe file under `base`.
    Denies absolute paths, up-levels, symlinks, hidden segments, and disallowed suffixes.
    """
    # Decode once & normalize
    s = urllib.parse.unquote_plus(user_input or "").strip()
    if not s or len(s) > MAX_PATH_LEN or "\x00" in s:
        return None

    # Normalize slashes (block backslash tricks on *nix)
    s = s.replace("\\", "/")

    # Block obvious bads early
    if s.startswith("/") or s.startswith(".") or "/." in s or ".." in s.split("/"):
        return None

    candidate = (base / s)

    try:
        real = candidate.resolve(strict=True)  # fail if not found
    except FileNotFoundError:
        return None

    # Must remain inside base
    try:
        real.relative_to(base)
    except ValueError:
        return None

    # No symlinks, regular files only
    if real.is_symlink() or not real.is_file():
        return None

    # No hidden path parts
    if any(part.startswith(".") for part in real.relative_to(base).parts):
        return None

    # Only allowed extensions
    if real.suffix.lower() not in ALLOWED_SUFFIXES:
        return None

    return real


@docs_bp.get("/api/docs")
@require_admin_session
def serve_doc():
    """
    SAFE document fetch:
      - Query param aliases: file|path|doc|name (default: sop-legacy.pdf)
      - Optional ?download=1 to force attachment
      - Enforces strict path checks (no traversal, no symlinks, no hidden files)
      - Only serves .pdf/.txt/.md from /app/docs
    """
    raw = _first_param("file", "path", "doc", "name") or "sop-legacy.pdf"
    target = _safe_resolve(DOCS_DIR, raw)
    if target is None:
        # Generic not_found so we don't leak path rules
        return jsonify({"error": "not_found"}), 404

    force_download = request.args.get("download", "0").lower() in ("1", "true", "yes")
    mime, _ = mimetypes.guess_type(target.name)
    resp = send_file(target, mimetype=mime or "application/octet-stream", as_attachment=force_download)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Checkpoint"] = "docs-safe"
    return resp


@docs_bp.get("/api/docs/list")
@require_admin_session
def list_docs():
    """
    SAFE listing of allowed docs under /app/docs (recurses, skips hidden/symlinks/disallowed types).
    """
    files = []
    for p in sorted(DOCS_DIR.rglob("*")):
        # Skip dirs, symlinks, hidden segments, and disallowed suffixes
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(DOCS_DIR)
        if any(part.startswith(".") for part in rel.parts):
            continue
        if p.suffix.lower() not in ALLOWED_SUFFIXES:
            continue
        try:
            size = p.stat().st_size
        except Exception:
            size = 0
        files.append({"path": rel.as_posix(), "size": size})
    return jsonify({"base": "/app/docs", "count": len(files), "files": files})

