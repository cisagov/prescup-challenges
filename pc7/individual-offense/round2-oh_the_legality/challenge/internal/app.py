# service_client.py
import socket
import json
import time

PORT = 55454
SECRET_KEY = "ERROR404"

TARGET_HOSTS = ["site", "fileserver"]

counter = 0

def resolve_targets(hosts, port):
    """
    Resolve hostnames to a list of (family, sockaddr) tuples.
    Includes all results (e.g., multiple A records).
    """
    targets = []
    for host in hosts:
        try:
            # 0 = any family, SOCK_DGRAM for UDP
            infos = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)
            for family, socktype, proto, canonname, sockaddr in infos:
                # sockaddr is (ip, port) for IPv4 or (ip, port, flow, scope) for IPv6
                targets.append((family, sockaddr))
        except socket.gaierror as e:
            print(f"[WARN] DNS resolution failed for {host}: {e}")
    # Deduplicate (same IP may appear multiple times)
    seen = set()
    uniq = []
    for family, sockaddr in targets:
        key = (family, sockaddr)
        if key not in seen:
            seen.add(key)
            uniq.append((family, sockaddr))
    return uniq


while True:
    try:
        command_data = {
            "key": SECRET_KEY,
            "command": "run",
            "count": counter,
            "shell": "PowerShell",
        }
        payload = json.dumps(command_data).encode("utf-8")

        targets = resolve_targets(TARGET_HOSTS, PORT)
        if not targets:
            print("[WARN] No targets resolved. Retrying...")
            time.sleep(1)
            continue

        # Send to each resolved target. Use a matching socket family per target.
        # (Simpler + avoids IPv4/IPv6 mismatch issues.)
        for family, sockaddr in targets:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                sent = s.sendto(payload, sockaddr)
                ip = sockaddr[0]
                print(f"[INFO] Sent {sent} bytes to {ip}:{PORT} (from hostname resolution)")

                # If you expect responses, you can try to read one per send.
                # Note: if both servers respond, you may want a loop/collection strategy.
                try:
                    data, addr = s.recvfrom(4096)
                    print(f"[SERVER RESPONSE from {addr}] {data.decode(errors='ignore')}")
                except socket.timeout:
                    print(f"[INFO] No response from {ip}, continuing...")

        counter += 1
        time.sleep(1)

    except OSError as e:
        print(f"[ERROR] {e}. Continuing...")
        time.sleep(1)
