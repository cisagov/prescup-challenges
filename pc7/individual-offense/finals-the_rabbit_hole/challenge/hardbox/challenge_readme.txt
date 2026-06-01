ELITE BOX — Challenge README

You have network access from your attacker container to this box on the docker network.
Services:
 - TCP custom service: port 31337
 - WASM runner: HTTP port 8080
 - Crypto vault: unix socket at /tmp/crypto.sock (local only)
 - SUID helper binary: /usr/local/bin/suid_helper (SUID root)

Goal: obtain root and read /root/ultimate_token.txt

Good luck.