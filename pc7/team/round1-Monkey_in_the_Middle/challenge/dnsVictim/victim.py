import socket
import subprocess
import sys
import time
import dns.resolver
import logging
import os

logging.basicConfig(
    format='%(asctime)s | %(levelname)s | %(message)s',
    level=logging.INFO
)

# --- Configuration from environment ---
flag = os.environ.get("dnsEavesdropToken")
tcp_token = os.environ.get("dnsManipulateToken")
dns_server = os.environ.get("DNS_SERVER")

if not dns_server:
    logging.error("Missing required environment variable DNS_SERVER.")
    sys.exit(1)

while True:  
    try:
        info = socket.getaddrinfo(dns_server, None, socket.AF_INET)
        if info:
            dns_server = info[0][4][0]  # resolved IP
            break
    except socket.gaierror as e:
        logging.warning(f"Resolution error for {dns_server}: {e}")

    logging.warning(f"Failed to resolve {dns_server}; retrying in 5 seconds...")
    time.sleep(5)

if not flag:
    raise ValueError("Environment variable FLAG is not set.")
if not tcp_token:
    raise ValueError("Environment variable TCP_TOKEN is not set.")
if not dns_server:
    raise ValueError("Environment variable DNS_SERVER is not set.")

def get_mac_for_ip(ip: str) -> str:
    try:
        output = subprocess.check_output(["ip", "neigh", "show", ip], text=True)
        for line in output.strip().splitlines():
            parts = line.split()
            if ip in parts and "lladdr" in parts:
                return parts[parts.index("lladdr") + 1]
    except Exception as e:
        logging.warning(f"[MAC] Could not retrieve MAC for {ip}: {e}")
    return "unknown"

encoded_flag = flag  # No encoding at the moment
if len(encoded_flag) > 64:
    logging.error(f"The provided token value is too long for a DNS label! {encoded_flag}")
    sys.exit(-1)


domain = f"{encoded_flag}.target.pccc"
tcp_port = 9001

# DNS setup with static nameserver
resolver = dns.resolver.Resolver()
resolver.nameservers = [dns_server]
resolver.cache = None  # Short lifetime should be sufficient, but just shut down completely to be safe
resolver.timeout = 2
resolver.lifetime = 3

while True:
    try:
        logging.info(f"Resolving {domain} using {dns_server} ({get_mac_for_ip(dns_server)})...")
        answers = resolver.resolve(domain, 'A')
        ip = answers[0].to_text()
        logging.info(f"Resolved to {ip}")

        logging.info(f"Connecting to {ip}:{tcp_port}...")
        with socket.create_connection((ip, tcp_port), timeout=5) as sock:
            sock.sendall(tcp_token.encode())
            logging.info(f"Sent TCP token.")
    except Exception as e:
        logging.warning(f"Error: {e}")

    time.sleep(5)
