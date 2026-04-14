# updater.py
import signal
import sys
import json, logging, os, shutil, subprocess, time, zipfile, hashlib
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from typing import Dict

USB_DIR = Path(os.environ.get("UPDATE_USB_DIR", "/mnt/usb"))
STAGING = "/opt/tc/update_staging"
CURRENT_VERSION_FILE = "/etc/traffic/version"

INSTALL_SH_SHA1 = "42b76ac20c83ae7ca5e47f5d0550ed0e5c29d222"

# Directory to watch for updates (override with UPDATE_USB_DIR env var if needed)
TARGET_NAME = "update.tcu"

os.makedirs(STAGING, exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def sha1_file(p):
    h = hashlib.sha1()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def read_current_version():
    try:
        with open(CURRENT_VERSION_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return "0.0.0"

def parse_semver(v):
    parts = []
    for tok in v.split("."):
        try: parts.append(int(tok))
        except ValueError: parts.append(0)
    return parts

def is_strictly_greater(new_v, cur_v):
    a, b = parse_semver(new_v), parse_semver(cur_v)
    n = max(len(a), len(b))
    a += [0]*(n-len(a)); b += [0]*(n-len(b))
    return a > b

def extract(zip_path):
    if os.path.exists(STAGING):
        shutil.rmtree(STAGING, ignore_errors=True)
    os.makedirs(STAGING, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(STAGING)
    man = os.path.join(STAGING, "manifest.json")
    inst = os.path.join(STAGING, "install.sh")
    hashes = os.path.join(STAGING, ".hashes")  # hidden inside package
    if not (os.path.exists(man) and os.path.exists(inst) and os.path.exists(hashes)):
        raise RuntimeError("Package missing manifest.json, install.sh, or .hashes")
    return man, inst, hashes

def load_manifest(path):
    with open(path) as f:
        return json.load(f)

def load_hash_table(hashes_path):
    table = {}
    with open(hashes_path) as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): 
                continue
            # format: sha1  files/foo  deadbeef...
            parts = s.split()
            if len(parts) < 3:
                continue
            alg, rel, digest = parts[0], parts[1], parts[2]
            if alg.lower() == "sha1":
                table[rel] = digest.lower()
    return table

def verify_install_sh(inst_path):
    have = sha1_file(inst_path)
    if have != INSTALL_SH_SHA1:
        logging.error("install.sh hash mismatch")
        return False
    return True

def verify_payload_integrity(manifest, hash_table):
    entries = manifest.get("files", [])
    if not entries:
        logging.error("manifest.json lists no files to verify.")
        return False
    for ent in entries:
        rel = ent.get("path")
        if not rel:
            logging.error("Malformed file entry in manifest.")
            return False
        src = os.path.normpath(os.path.join(STAGING, rel))
        if not src.startswith(STAGING):
            logging.error("Path traversal attempt: %s", rel)
            return False
        if not os.path.exists(src):
            logging.error("Missing file listed in manifest: %s", rel)
            return False
        want = hash_table.get(rel)
        if not want:
            logging.error("No hash in .hashes for %s", rel)
            return False
        have = sha1_file(src)
        if have != want:
            logging.error("SHA1 mismatch for %s", rel)
            return False
    return True

def log_install_sh(path: str, max_bytes: int = 32 * 1024):
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        text = data.decode("utf-8", errors="replace")
        logging.info("==== install.sh (first %d bytes) ====\n%s\n==== end install.sh ====", len(data), text)
        if os.path.getsize(path) > max_bytes:
            logging.info("install.sh truncated (file is %d bytes)", os.path.getsize(path))
    except Exception as e:
        logging.exception("Failed to log install.sh: %s", e)

def run_install():
    inst = os.path.join(STAGING, "install.sh")
    os.chmod(inst, 0o755)
    env = {**os.environ, "TCU_STAGING": STAGING}
    proc = subprocess.run(["/bin/bash", "install.sh"], cwd=STAGING, env=env)
    return proc.returncode

def process(zip_path):
    try:
        man_path, inst_path, hashes_path = extract(zip_path)
        manifest = load_manifest(man_path)
        hash_table = load_hash_table(hashes_path)

        # Version must increase
        new_v = manifest.get("fw_version", "0.0.0")
        cur_v = read_current_version()
        # if not is_strictly_greater(new_v, cur_v):
        #     logging.error("Rejected: fw_version %s is not greater than current %s", new_v, cur_v)
        #     return

        # Verify install.sh against device-hardcoded hash
        if not verify_install_sh(inst_path):
            return

        log_install_sh(inst_path)
        log_install_sh(inst_path.replace("install.sh", "files/update.sh"))

        # Verify payloads listed in manifest against .hashes
        if not verify_payload_integrity(manifest, hash_table):
            return
        
        rc = run_install()
        logging.info("install.sh exited %s", rc)
        if rc == 0:
            os.makedirs(os.path.dirname(CURRENT_VERSION_FILE), exist_ok=True)
            with open(CURRENT_VERSION_FILE, "w") as f:
                f.write(new_v + "\n")
    except Exception as e:
        logging.exception("Error processing update: %s", e)

def _file_is_stable(p: Path, checks: int = 5, interval: float = 0.2) -> bool:
    """Return True if file size stops changing across a few checks."""
    try:
        last = p.stat().st_size
    except FileNotFoundError:
        return False
    for _ in range(checks):
        time.sleep(interval)
        try:
            cur = p.stat().st_size
        except FileNotFoundError:
            return False
        if cur == last:
            return True
        last = cur
    return False

class UpdateHandler(FileSystemEventHandler):
    def __init__(self) -> None:
        super().__init__()
        self._last_mtime: Dict[Path, float] = {}

    def on_created(self, event):
        self._maybe_handle(event.src_path)

    def on_modified(self, event):
        self._maybe_handle(event.src_path)
    
    def on_moved(self, event):
        self._maybe_handle(event.dest_path)


    def _maybe_handle(self, src_path: str) -> None:
        p = Path(src_path)
        if p.name != TARGET_NAME or p.is_dir():
            return
        try:
            mtime = p.stat().st_mtime
        except FileNotFoundError:
            return
        if self._last_mtime.get(p) == mtime:
            return  # unchanged since last event
        self._last_mtime[p] = mtime

        logging.info("Detected %s change: %s", TARGET_NAME, p)
        if not _file_is_stable(p):
            logging.info("Skipped %s: not stable yet", p)
            return
        try:
            process(str(p))
            logging.info("Processed %s", p)
        except Exception:
            logging.exception("Error processing %s", p)

def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not USB_DIR.exists():
        logging.info("Creating %s", USB_DIR)
        USB_DIR.mkdir(parents=True, exist_ok=True)
        
    # One-time startup processing
    initial = USB_DIR / TARGET_NAME
    if initial.exists() and initial.is_file():
        logging.info("Startup: found existing %s, processing once", initial)
        try:
            process(str(initial))
            logging.info("Startup processing complete")
        except Exception:
            logging.exception("Startup processing failed")

    handler = UpdateHandler()
    try:
        observer = Observer()
        observer.schedule(handler, str(USB_DIR), recursive=False)
        observer.start()
    except OSError as e:
        if getattr(e, "errno", None) == 24:
            logging.error("inotify limit hit; falling back to polling observer")
            observer = PollingObserver(timeout=1.0)
            observer.schedule(handler, str(USB_DIR), recursive=False)
            observer.start()
        else:
            raise
    logging.info("Watchdog started for %s (target: %s)", USB_DIR, TARGET_NAME)

    # Graceful shutdown
    stop = False
    def _sigterm(signum, _frame):
        nonlocal stop
        logging.warning("Received signal %s; stopping", signum)
        stop = True
    signal.signal(signal.SIGINT, _sigterm)
    signal.signal(signal.SIGTERM, _sigterm)

    try:
        while not stop:
            time.sleep(0.5)
    finally:
        observer.stop()
        observer.join(timeout=5)
        logging.info("Watchdog stopped")
    return 0

if __name__ == "__main__":
    sys.exit(main())
