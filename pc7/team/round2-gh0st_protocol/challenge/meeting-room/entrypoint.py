import os
import socket
import time
import subprocess
import sys

def wait_for_tcp(host: str, port: int, seconds: int) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(1)

    # IMPORTANT: no restart policy available, so we do NOT exit.
    # We start the service anyway and let runtime requests handle transient failures.
    print(
        f"[meeting-room] WARNING: Dependency not reachable after {seconds}s: {host}:{port}. "
        "Starting anyway.",
        file=sys.stderr,
    )

def main() -> int:
    host = os.getenv("WAIT_HOST", "gh0st-protocol")
    port = int(os.getenv("WAIT_PORT", "8081"))
    seconds = int(os.getenv("WAIT_SECONDS", "120"))

    wait_for_tcp(host, port, seconds)

    # Start the actual Flask app
    return subprocess.call([sys.executable, "suitcase_gui.py"])

if __name__ == "__main__":
    raise SystemExit(main())

