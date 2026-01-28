#!/usr/bin/env python3
import http.server
import socketserver
import threading
import os
import sys
import time

# ------------------------------
# Configuration
# ------------------------------
FILES_TO_SERVE = [
    "token1.txt",
    "token3.txt",
    "token4.txt",
]

SERVE_DIR = "/"   # Files live in /
PORT = 80

served_files = set()

# ------------------------------
# Custom Handler
# ------------------------------
class FileOnceHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Force the handler to serve from SERVE_DIR ("/")
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def do_GET(self):
        global served_files

        # Trim leading slash and strip any query string/fragments
        req_path = self.path.split("?", 1)[0].split("#", 1)[0].lstrip("/")

        # Only serve the specified files
        if req_path not in FILES_TO_SERVE:
            self.send_error(404, "File not available")
            return

        abs_path = os.path.join(SERVE_DIR, req_path)

        # Must exist in /
        if not os.path.isfile(abs_path):
            self.send_error(404, "File not found on server")
            return

        # Serve manually so we know when transmission finishes
        file_size = os.path.getsize(abs_path)

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(file_size))
        self.end_headers()

        # Stream file & detect completion
        try:
            with open(abs_path, "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            self.wfile.flush()
        except BrokenPipeError:
            # Client disconnected mid-transfer; do not delete the file
            print(f"[!] Client disconnected early; NOT deleting: {abs_path}")
            return
        except Exception as e:
            print(f"[!] Error serving {abs_path}: {e}")
            return

        # Mark as served
        print(f"[+] Served: {abs_path}")
        served_files.add(req_path)

        # Delete file using bash via os.system()
        # Use a quoted absolute path to avoid mistakes.
        rm_cmd = f"/bin/bash -c \"rm -f '{abs_path}'\""
        rc = os.system(rm_cmd)
        if rc != 0:
            print(f"[!] rm command failed for {abs_path} (exit code {rc})")
        else:
            print(f"[+] Deleted (rm -f): {abs_path}")

        # Confirm deletion before allowing shutdown logic
        while os.path.exists(abs_path):
            print(f"[-] Waiting for {abs_path} to be removed...")
            time.sleep(0.2)

        print(f"[+] Confirmed deleted: {abs_path}")

        # If all served -> shutdown
        if served_files == set(FILES_TO_SERVE):
            # Also confirm all are actually gone (belt + suspenders)
            for f in FILES_TO_SERVE:
                p = os.path.join(SERVE_DIR, f)
                while os.path.exists(p):
                    print(f"[-] Waiting for final confirmation delete: {p}")
                    time.sleep(0.2)

            print("[+] All files served and confirmed deleted. Shutting down HTTP server...")
            threading.Thread(target=shutdown_server, daemon=True).start()

# ------------------------------
# Server Shutdown
# ------------------------------
def shutdown_server():
    """Trigger server shutdown (must run in separate thread)."""
    time.sleep(0.5)  # small delay to let final response finish cleanly
    httpd.shutdown()

# ------------------------------
# Main Server Startup
# ------------------------------
if __name__ == "__main__":
    # Ensure files exist at /
    for f in FILES_TO_SERVE:
        p = os.path.join(SERVE_DIR, f)
        if not os.path.isfile(p):
            print(f"Error: Required file not found: {p}")
            sys.exit(1)

    handler = FileOnceHandler

    # Allow fast restarts without "Address already in use"
    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReusableTCPServer(("0.0.0.0", PORT), handler) as httpd:
        print(f"[+] Serving from {SERVE_DIR} on port {PORT}")
        httpd.serve_forever()
