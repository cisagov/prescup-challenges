#!/usr/bin/env python3
import socket
import threading
from pathlib import Path
import time

HOST = "0.0.0.0"
PORT = 31337

STATE_DIR = Path("/opt/lancer/state")
PATCH_FILE = STATE_DIR / "patch_level"
BANNER_FILE = STATE_DIR / "banner"

PATCH_NOTES = {
    1: "P1 — Legacy QA harness. Will fix 'echo' issue in next patch.",
    2: "P2 — Basic metacharacter stripping + double-quoting.",
    3: "P3 — Extended stripping set.",
    4: "P4 — Migrated to Exim macro expander for 'safe' templating.",
}

MAILING_LIST = """
aaron.smith@staging.lancer.pccc
adam.brown@staging.lancer.pccc
alex.johnson@staging.lancer.pccc
alice.wright@staging.lancer.pccc
andrew.miller@staging.lancer.pccc
anna.lee@staging.lancer.pccc
audit@staging.lancer.pccc
ben.clark@staging.lancer.pccc
brandon.hall@staging.lancer.pccc
brian.young@staging.lancer.pccc
carol.king@staging.lancer.pccc
chris.evans@staging.lancer.pccc
daniel.scott@staging.lancer.pccc
david.adams@staging.lancer.pccc
elena.martinez@staging.lancer.pccc
emily.turner@staging.lancer.pccc
eric.carter@staging.lancer.pccc
frank.moore@staging.lancer.pccc
george.white@staging.lancer.pccc
hannah.green@staging.lancer.pccc
ian.thomas@staging.lancer.pccc
james.walker@staging.lancer.pccc
jane.collins@staging.lancer.pccc
jason.harris@staging.lancer.pccc
jessica.lopez@staging.lancer.pccc
john.doe@staging.lancer.pccc
julia.reed@staging.lancer.pccc
kevin.baker@staging.lancer.pccc
laura.price@staging.lancer.pccc
linda.ross@staging.lancer.pccc
mark.cooper@staging.lancer.pccc
matthew.edwards@staging.lancer.pccc
megan.fisher@staging.lancer.pccc
michael.parker@staging.lancer.pccc
natalie.brooks@staging.lancer.pccc
nick.hughes@staging.lancer.pccc
olivia.rivera@staging.lancer.pccc
paul.ward@staging.lancer.pccc
peter.long@staging.lancer.pccc
rachel.cook@staging.lancer.pccc
robert.bell@staging.lancer.pccc
ryan.murphy@staging.lancer.pccc
sarah.bailey@staging.lancer.pccc
sean.wood@staging.lancer.pccc
steve.kelly@staging.lancer.pccc
tina.howard@staging.lancer.pccc
tommy.ramirez@staging.lancer.pccc
victor.hernandez@staging.lancer.pccc
william.perez@staging.lancer.pccc
zoe.sanders@staging.lancer.pccc
"""

HELP = (
    "📧 LANCER Mail PATCH CONSOLE v1.2\n"
    "--------------------\n"
    "Commands:\n"
    "  HELP               Show this help menu\n"
    "  LIST               Shows valid email addresses to test FROM\n"
    "  STATUS             Show the current patch level\n"
    "  PATCH <1-4>         Set active patch level\n"
    "  NEXT               Increment patch level (wraps at 5)\n"
    "  QUIT/EXIT          Exit the patch console.\n"
    "\n"
    "Note: SMTP service is on port 2525 (host: staging.lancer.pccc).\n"
)

def set_patch(level: int) -> str:
    if level not in PATCH_NOTES:
        return "ERR Invalid patch level (use 1-5)\n"

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PATCH_FILE.write_text(str(level) + "\n")
    # Banner is evaluated at connection time via readfile(), so Exim picks this up live.
    BANNER_FILE.write_text(f"STAGING — {PATCH_NOTES[level]}\n")

    return f"OK Patch set to {level}/4\n{PATCH_NOTES[level]}\n"

def get_patch() -> int:
    try:
        v = int(PATCH_FILE.read_text().strip())
        return v if v in PATCH_NOTES else 1
    except Exception:
        return 1

def status() -> str:
    level = get_patch()
    return f"STATUS Patch {level}/4\n{PATCH_NOTES[level]}\n"

def handle_client(conn: socket.socket, addr):
    conn.settimeout(300)
    try:
        conn.sendall(HELP.encode())
        buf = b""
        while True:
            conn.sendall(b"> ")
            data = conn.recv(4096)
            if not data:
                break
            buf += data
            if b"\n" not in buf:
                continue
            line, _, buf = buf.partition(b"\n")
            cmd = line.decode(errors="replace").strip()
            if not cmd:
                continue
            parts = cmd.split()
            op = parts[0].upper()

            if op == "HELP":
                conn.sendall(HELP.encode())
            elif op == "LIST":
                conn.sendall(MAILING_LIST.encode())
            elif op == "STATUS":
                conn.sendall(status().encode())
            elif op == "PATCH":
                if len(parts) != 2 or not parts[1].isdigit():
                    conn.sendall(b"ERR Usage: PATCH <1-4>\n")
                else:
                    conn.sendall(set_patch(int(parts[1])).encode())
            elif op == "NEXT":
                level = get_patch()
                level = 1 if level >= 4 else level + 1
                conn.sendall(set_patch(level).encode())
            elif op in ("QUIT", "EXIT"):
                conn.sendall(b"BYE\n")
                break
            else:
                conn.sendall(b"ERR Unknown command. Type HELP.\n")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    # initialize state if missing
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not PATCH_FILE.exists():
        set_patch(1)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(50)

    print(f"[patchd] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    main()
