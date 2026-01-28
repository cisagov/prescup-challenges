#!/usr/bin/env python3
import http.server
import socketserver
import threading
import os
import sys

# ------------------------------
# Configuration
# ------------------------------
FILES_TO_SERVE = [
    "token1.txt",
    "token2.txt",
#    "token3.txt",
#    "token4.txt",
#    "token5.txt",
#    "token6.txt",
    "token7.txt",
#    "token8.txt",
#    "token9.txt",
#    "token10.txt"
]

PORT = 80

# Track which files were fully transmitted
served_files = set()

# ------------------------------
# Custom Handler
# ------------------------------
class FileOnceHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        global served_files

        # Trim leading slash
        req_path = self.path.lstrip("/")

        # Only serve the three files
        if req_path not in FILES_TO_SERVE:
            self.send_error(404, "File not available")
            return

        # Serve the file manually so we know when transmission finishes
        if not os.path.exists(req_path):
            self.send_error(404, "File not found on server")
            return

        file_size = os.path.getsize(req_path)

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(file_size))
        self.end_headers()

        # Stream file & detect completion
        with open(req_path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)

        # Mark this file as served
        print(f"[+] Served: {req_path}")
        served_files.add(req_path)

        # If all 3 served → stop server
        if served_files == set(FILES_TO_SERVE):
            print("[+] All files served. Shutting down HTTP server...")
            threading.Thread(target=shutdown_server, daemon=True).start()

# ------------------------------
# Server Shutdown
# ------------------------------
def shutdown_server():
    """Trigger server shutdown (must run in separate thread)."""
    httpd.shutdown()

# ------------------------------
# Main Server Startup
# ------------------------------
if __name__ == "__main__":
    # Ensure files exist
    for f in FILES_TO_SERVE:
        if not os.path.isfile(f):
            print(f"Error: Required file not found: {f}")
            sys.exit(1)

    handler = FileOnceHandler

    with socketserver.TCPServer(("0.0.0.0", PORT), handler) as httpd:
        print(f"[+] Serving files on port {PORT}")
        httpd.serve_forever()

