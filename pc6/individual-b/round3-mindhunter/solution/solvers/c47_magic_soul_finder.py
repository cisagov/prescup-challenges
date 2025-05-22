#!/usr/bin/env python3

import requests
import argparse

# Full list from your explorer.js (static endpoints)
endpoint_list = [
    "access", "activity", "admin", "admin_panel", "analytics", "api", "audit", "audit_log", "backup", "billing",
    "cache", "cart", "checkout", "config", "customer", "dashboard", "data", "database", "debug", "developer",
    "download", "email", "encode", "events", "export", "fetch", "file", "help", "hooks", "import", "integrations",
    "jobs", "login", "logout", "logs", "manual", "messages", "monitor", "notifications", "order", "payment",
    "permissions", "preferences", "profile", "queue", "renew", "report", "reset", "restore", "roles", "search",
    "security", "server_status", "sessions", "settings", "status", "stop", "subscription", "support", "sync",
    "system", "team", "timeout", "tokens", "update", "upload", "user", "user_settings", "verification",
    "webhooks", "worker", "workspace"
]

def test_endpoints(host, port, headers):
    base_url = f"http://{host}:{port}"
    magic_endpoints = []
    normal_endpoints = []

    print(f"[+] Testing {len(endpoint_list)} static endpoints...")
    for ep in endpoint_list:
        url = f"{base_url}/{ep}"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            status = resp.status_code
            if status == 403:
                print(f"❌ [MAGIC] {ep} responded with 403 Forbidden")
                magic_endpoints.append(f"/{ep}")
            elif status == 200:
                print(f"✅ [Normal] {ep} responded with 200 OK")
                normal_endpoints.append(f"/{ep}")
            else:
                print(f"⚠️ {ep} responded with {status}")
        except Exception as e:
            print(f"[!] Error testing {ep}: {e}")

    print("\n🎯 Summary:")
    print(f"Magic Endpoints (403 Forbidden): {magic_endpoints}")
    print(f"Normal Endpoints (200 OK): {normal_endpoints}")

def main():
    parser = argparse.ArgumentParser(description="Brute Force Magic Endpoints (Static List)")
    parser.add_argument("--host", required=True, help="Target host (e.g., 10.4.4.21)")
    parser.add_argument("--port", required=True, type=int, help="Target port (e.g., 5004)")
    parser.add_argument("--header", action="append", help="Optional headers to add (format: Key:Value)", default=[])
    args = parser.parse_args()

    # Build headers dictionary
    headers = {}
    for h in args.header:
        try:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()
        except:
            print(f"[!] Invalid header format: {h} (use Key:Value)")
            return

    test_endpoints(args.host, args.port, headers)

if __name__ == "__main__":
    main()
