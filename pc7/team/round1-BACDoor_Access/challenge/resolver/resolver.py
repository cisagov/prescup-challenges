#!/usr/bin/env python3
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
from urllib.parse import parse_qs

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DEVICES_FILE = "/devices.json"

VISIBLE_NET_NAME = "platform_net"
REPORTED_NET_NAME = "engineering_net"

EXPECTED_HOSTS = [
    "lecturelights.pccc",
    "lecturehvac.pccc",
    "englights.pccc",
    "enghvac.pccc",
    "security.pccc",
    "firesafety.pccc",
    "powermonitoring.pccc",
    "weather.pccc",
    "serverroom.pccc",
    "evcharging.pccc"
]

def recognize(ip_addresses, client_ip, reported_hostname):
    """
    Given a list of IPs reported by the client and the client's source IP,
    determine visible/reported IPs and store an entry with hostname and
    network mappings in devices.json.
    """

    # Deduplicate while preserving order
    uniq_ips = []
    for ip in ip_addresses:
        if ip not in uniq_ips:
            uniq_ips.append(ip)

    visible_ip = None
    reported_ip = None

    # If the client IP is in the list, treat that as "public"
    if client_ip in uniq_ips:
        visible_ip = client_ip
        others = [ip for ip in uniq_ips if ip != client_ip]
        reported_ip = others[0] if others else None
    elif len(uniq_ips) >= 2:
        # Fallback: assume first is public, second is private
        visible_ip, reported_ip = uniq_ips[0], uniq_ips[1]
    elif len(uniq_ips) == 1:
        visible_ip = uniq_ips[0]

    # Add hostname
    hostname = (reported_hostname or "").strip() or visible_ip or client_ip or "unknown"

    device = {
        "hostname": hostname,
        VISIBLE_NET_NAME: visible_ip,
        REPORTED_NET_NAME: reported_ip,
    }

    # Load existing devices
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as f:
            devices = json.load(f)
            if not isinstance(devices, list):
                devices = []
    except (FileNotFoundError, json.JSONDecodeError):
        devices = []

    # Update existing entry (match on hostname or public IP), or append
    updated = False
    for entry in devices:
        if (
            entry.get("hostname") == hostname
        ):
            entry.update(device)
            updated = True
            break

    if not updated:
        devices.append(device)

    # Write back atomically-ish (simple overwrite; single-threaded server)
    with open(DEVICES_FILE, "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=2)

    logger.info("Recorded device: %s", device)


class DeviceHandler(BaseHTTPRequestHandler):
    def _send_json(self, obj, status=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/register":
            self._send_json({"error": "Not found"}, status=404)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        params = parse_qs(body)

        client_ip = self.client_address[0]

        address_param = params.get("address", [""])[0].strip()
        reported_hostname = params.get("hostname", [""])[0].strip()

        # First: hostname + raw address presence
        if not reported_hostname or not address_param:
            logger.error(
                "Invalid /register from %s: hostname=%r address=%r",
                client_ip,
                reported_hostname,
                address_param,
            )
            try:
                self._send_json(
                    {"error": "hostname and address are required"}, status=400
                )
            except Exception:
                pass
            sys.exit(1)

        ip_addresses = [ip.strip() for ip in address_param.split(",") if ip.strip()]

        if not ip_addresses:
            logger.error(
                "Invalid /register from %s: no valid IPs parsed from address=%r",
                client_ip,
                address_param,
            )
            try:
                self._send_json(
                    {"error": "at least one IP address is required"}, status=400
                )
            except Exception:
                pass
            sys.exit(1)

        logger.info(
            "Received /register from %s (%s) with IPs: %s",
            client_ip,
            reported_hostname,
            ip_addresses,
        )

        recognize(ip_addresses, client_ip, reported_hostname)

        self._send_json({"status": "ok", "count": len(ip_addresses)})


    def do_GET(self):
        if self.path != "/list":
            self._send_json({"error": "Not found"}, status=404)
            return

        try:
            with open(DEVICES_FILE, "r", encoding="utf-8") as f:
                devices = json.load(f)
            if not isinstance(devices, list):
                devices = []
        except FileNotFoundError:
            logger.info("Devices file not found, returning incomplete.")
            self._send_json({"status": "incomplete", "reason": "no devices yet"}, status=200)
            return
        except json.JSONDecodeError:
            logger.warning("Devices file is not valid JSON, returning incomplete.")
            self._send_json({"status": "incomplete", "reason": "bad json"}, status=200)
            return

        # Build a set of hostnames we've actually seen
        seen = {d.get("hostname") for d in devices if "hostname" in d}

        # Expected hosts missing?
        missing = [h for h in EXPECTED_HOSTS if h not in seen]

        if missing:
            logger.info("List incomplete; missing hosts: %s", missing)
            self._send_json({
                "status": "incomplete",
                "missing": missing,
                "seen": list(seen)
            }, status=200)
            return

        # All expected hosts present → return the final list
        self._send_json(devices)

    def log_message(self, format, *args):
        # Route default HTTP server logs through logging
        logger.info("%s - %s", self.address_string(), format % args)


def run(host="0.0.0.0", port=80):
    server = HTTPServer((host, port), DeviceHandler)
    logger.info("Starting server on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server.")
        server.server_close()


if __name__ == "__main__":
    run()
