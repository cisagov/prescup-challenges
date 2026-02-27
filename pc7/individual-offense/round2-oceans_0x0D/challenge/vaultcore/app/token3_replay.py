from __future__ import annotations
import base64, socket, struct, zlib
from dataclasses import dataclass

MAGIC = b"RPLY"

@dataclass(frozen=True)
class ReplayResponse:
    ok: bool
    raw: bytes

def build_frame(cmd: bytes, cmd_data: bytes, ver: int = 1, flags: int = 0) -> bytes:
    payload = cmd + cmd_data
    header = MAGIC + bytes([ver & 0xFF, flags & 0xFF]) + struct.pack("<H", len(payload))
    crc = zlib.crc32(header + payload) & 0xFFFFFFFF
    return header + payload + struct.pack("<I", crc)

def send_frame(host: str, port: int, frame: bytes, timeout_s: float = 1.0) -> ReplayResponse:
    # replayd protocol: 4-byte LE length then frame
    if len(frame) > 8192:
        raise ValueError("frame too big")
    msg = struct.pack("<I", len(frame)) + frame
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        s.connect((host, port))
        s.sendall(msg)
        data = s.recv(65535)
        return ReplayResponse(ok=data.startswith(b"OK "), raw=data)
    finally:
        try: s.close()
        except Exception: pass

def parse_ok_payload(resp: ReplayResponse) -> bytes:
    if not resp.ok:
        return b""
    # "OK <base64>"
    b64 = resp.raw.split(b" ", 1)[1].strip()
    try:
        return base64.b64decode(b64, validate=False)
    except Exception:
        return b""
