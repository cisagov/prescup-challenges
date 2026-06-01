import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

ALLOWED_DURATIONS = {15, 30, 60, 120}
_lock = threading.Lock()
_state = "idle"
_log: list[str] = []
_export_ready = False
_stop_event = threading.Event()

TOKEN2 = os.environ.get("TOKEN2", "PCCC{SHN-A2-f9277cad}")
TOKEN4 = os.environ.get("TOKEN4", "PCCC{SHN-A4-a842ec49}")


def _append(line: str) -> None:
    with _lock:
        _log.append(line)
        del _log[:-20]


def _guard_byte() -> int:
    return (0x13 + 0x37 + 4) & 0xFF


def _build_silent_step_frames(token: str) -> list[dict]:
    raw = token.encode("utf-8")
    chunk_size = (len(raw) + 3) // 4
    chunks = [raw[i : i + chunk_size] for i in range(0, len(raw), chunk_size)]
    while len(chunks) < 4:
        chunks.append(b"")

    guard = _guard_byte()
    frames = []
    for seq, chunk in enumerate(chunks[:4]):
        header = bytes([0x13, 0x37, 0x20, seq, 0x13, 0x37, seq])
        body = bytes(b ^ guard for b in chunk)
        frames.append(
            {
                "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "component": "burstmux",
                "tag": "silent-step",
                "seq": seq,
                "frame_hex": (header + body).hex(),
            }
        )
    return frames


def _build_export_lines() -> list[dict]:
    digest = hashlib.sha256(TOKEN4.encode("utf-8")).hexdigest()[:10]
    lines: list[dict] = [
        {
            "ts": "2026-03-14T21:10:02Z",
            "component": "dashboard",
            "event": "bookmark-load",
            "path": "/mission",
            "operator": "night-shift",
        },
        {
            "ts": "2026-03-14T21:10:09Z",
            "component": "relay-audit",
            "event": "trusted-first-hop",
            "target": "http://sp-dashboard.ninja:3000/maintenance/jump",
            "note": "followed redirect chain to terminal maintenance target",
        },
    ]

    lines.extend(_build_silent_step_frames(TOKEN2))

    lines.extend(
        [
            {
                "ts": "2026-03-14T21:10:14Z",
                "component": "ops-panel",
                "event": "response-detail",
                "mode": "extended",
            },
            {
                "ts": "2026-03-14T21:10:17Z",
                "component": "coap-audit",
                "event": "translation",
                "raw_target": "coap://sp-coap.ninja/telemetry/%252e%252e/admin/bootstrap?ticket=redacted",
                "decoded_once": "/telemetry/%2e%2e/admin/bootstrap",
                "normalized_path": "/admin/bootstrap",
                "status": "4.03",
                "reason": "bridge ticket required",
            },
            {
                "ts": "2026-03-14T21:10:18Z",
                "component": "coap-audit",
                "event": "ticket-preview",
                "digest": digest,
                "note": "bootstrap precedes material and finalize",
            },
        ]
    )
    return lines


EXPORT_LINES = _build_export_lines()


def _run_replay(duration: int) -> None:
    global _state, _export_ready
    _append("[replay] initializing deterministic emission")
    steps = min(max(duration // 5, 3), 6)

    for step in range(steps):
        if _stop_event.is_set():
            _append("[replay] stop requested")
            break
        _append(f"[replay] stage {step + 1}/{steps} emitted")
        time.sleep(2)

    if not _stop_event.is_set():
        _append("[replay] export assembled")
        with _lock:
            _export_ready = True

    with _lock:
        _state = "idle"
    _stop_event.clear()


@app.get("/")
def home():
    return "Replay API ready.\n"


@app.post("/api/replay/start")
def start():
    global _state, _export_ready
    payload = request.get_json(silent=True) or {}
    duration = payload.get("duration")
    if duration not in ALLOWED_DURATIONS:
        return jsonify({"state": "error", "detail": "invalid duration"}), 400

    with _lock:
        if _state == "running":
            return jsonify({"state": "running"}), 409
        _state = "running"
        _export_ready = False
        _log.clear()

    thread = threading.Thread(target=_run_replay, args=(duration,), daemon=True)
    thread.start()
    return jsonify({"state": "started"}), 200


@app.post("/api/replay/stop")
def stop():
    global _state
    _stop_event.set()
    with _lock:
        _state = "idle"
    return jsonify({"state": "stopped"}), 200


@app.get("/api/replay/status")
def status():
    with _lock:
        return jsonify({"state": _state, "log": list(_log), "export_ready": _export_ready}), 200


@app.get("/api/replay/export")
def export():
    with _lock:
        if not _export_ready:
            return jsonify({"detail": "replay export not ready"}), 409

    body = "\n".join(json.dumps(line, sort_keys=True) for line in EXPORT_LINES) + "\n"
    return Response(body, mimetype="application/x-ndjson")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000, debug=False)
