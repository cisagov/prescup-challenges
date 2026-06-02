# Retrives the handshake and command needed to send to the uplink to get Token 1
#!/usr/bin/env python3
import socket, hashlib

def get_local_ip(target_host="null-horizon.local", target_port=31337):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_host, target_port))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def compute_handshake_hex(ip_str: str) -> str:
    ip_bytes = socket.inet_aton(ip_str)
    K = bytearray(hashlib.md5(ip_bytes).digest()[:4])  # first 4 bytes
    for i in range(4):
        K[i] ^= 0x5A

    msg = bytearray(b"OPTO")
    for i in range(4):
        msg[i] ^= K[i]
    return msg.hex()

if __name__ == "__main__":
    my_ip = get_local_ip()
    h = compute_handshake_hex(my_ip)
    print("Your IP as seen by implant:", my_ip)
    print("Run this in the implant shell:")
    print(f"handshake {h}")