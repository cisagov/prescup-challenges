import logging
import os
import sys
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import subprocess
import threading
import dns.resolver
import socket
from selenium.common.exceptions import WebDriverException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from urllib.parse import urlparse
from selenium.webdriver.chrome.service import Service
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import threading


logging.basicConfig(
    format='%(asctime)s | %(threadName)s | %(levelname)s | %(message)s',
    level=logging.INFO
)

TARGET_URL = os.environ.get("TARGET_URL")
TOKEN_EAVESDROP = os.environ.get("tokenHTTPEavesdrop")
TOKEN_TYPING = os.environ.get("tokenHTTPType")
TOKEN_COOKIE_LAX = os.environ.get("tokenCookieLax")
TOKEN_COOKIE_STRICT = os.environ.get("tokenCookieStrict")
EXTERNAL_DOMAIN = "external.target.pccc" # ENV later?
DNS_SERVER = os.environ.get("DNS_SERVER")

if not DNS_SERVER:
    logging.error("Missing required environment variable DNS_SERVER.")
    sys.exit(1)

while True: 
    try:
        info = socket.getaddrinfo(DNS_SERVER, None, socket.AF_INET)
        if info:
            DNS_SERVER = info[0][4][0]  # resolved IP
            break
    except socket.gaierror as e:
        logging.warning(f"Resolution error for {DNS_SERVER}: {e}")

    logging.warning(f"Failed to resolve {DNS_SERVER}; retrying in 5 seconds...")
    time.sleep(5)

# Log all values
logging.info(f"TARGET_URL: {TARGET_URL}")
logging.info(f"TOKEN_EAVESDROP: {TOKEN_EAVESDROP}")
logging.info(f"TOKEN_TYPING: {TOKEN_TYPING}")
logging.info(f"TOKEN_COOKIE_LAX: {TOKEN_COOKIE_LAX}")
logging.info(f"TOKEN_COOKIE_STRICT: {TOKEN_COOKIE_STRICT}")
logging.info(f"EXTERNAL_DOMAIN: {EXTERNAL_DOMAIN}")  
logging.info(f"DNS_SERVER: {DNS_SERVER}")  

# Check that none are missing
if None in (TARGET_URL, TOKEN_EAVESDROP, TOKEN_TYPING, TOKEN_COOKIE_LAX, TOKEN_COOKIE_STRICT, EXTERNAL_DOMAIN, DNS_SERVER):
    logging.error("Missing one or more required environment variables.")
    sys.exit(1)

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

def start_dns_watch(domain, dns_server):
    def dns_loop():
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.cache = None
        resolver.timeout = 2
        resolver.lifetime = 3
        
        last_ip = None

        while True:
            try:
                logging.info(f"Resolving {domain} using {dns_server} ({get_mac_for_ip(dns_server)})...")
                answers = resolver.resolve(domain, 'A')
                ip = answers[0].to_text()

                if ip != last_ip:
                    last_ip = ip
                    logging.info(f"Resolved to {ip}, updating /etc/hosts...")

                    try:
                        with open("/etc/hosts", "r") as f:
                            lines = [line for line in f if domain not in line]
                    except FileNotFoundError:
                        lines = []

                    lines.append(f"{ip} {domain}\n")

                    with open("/etc/hosts", "w") as f:
                        f.writelines(lines)

                    logging.info(f"Updated /etc/hosts with: {ip} {domain}")
                else:
                    logging.info(f"No change in IP for {domain} (still {ip})")
            except Exception as e:
                logging.warning(f"DNS resolution error: {e}")

            time.sleep(5)

    thread = threading.Thread(target=dns_loop, daemon=True)
    thread.start()
    return thread

def start_http_server(port=80):
    server = ThreadingHTTPServer(("0.0.0.0", port), SimpleHTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logging.info("Started in-process HTTP server on port %s", port)
    return server

# --- Headless browser setup ---
options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument(f"--user-agent={TOKEN_EAVESDROP}")

service = Service(executable_path='/usr/bin/chromedriver') 
driver = webdriver.Chrome(service=service, options=options)

driver.execute_cdp_cmd("Network.enable", {})
driver.execute_cdp_cmd("Network.setCacheDisabled", {"cacheDisabled": True})

if not EXTERNAL_DOMAIN:
    raise ValueError("EXTERNAL_URL environment variable is not set.")

# Write to /etc/hosts
with open("/etc/hosts", "a") as f:
    f.write(f"127.0.0.1 {EXTERNAL_DOMAIN}\n")
logging.info(f"Mapped {EXTERNAL_DOMAIN} to 127.0.0.1 in /etc/hosts")

# Start HTTP server in background
# server = start_http_server(80)
proc = subprocess.Popen(["python3", "-m", "http.server", "80"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
logging.info(f"Started local HTTP server for {EXTERNAL_DOMAIN} on port 80")

# Set up a cookie in the "external" site they want to steal from
# First, try to load the external domain up to 3 times
for attempt in range(3):
    try:
        driver.get(f"http://{EXTERNAL_DOMAIN}")  # must succeed, even if empty page
        break  # success
    except Exception as e:
        if attempt == 2:
            raise  # rethrow on final failure
        logging.info("Failed to connect - Retrying in 5 seconds...")
        time.sleep(5)

driver.add_cookie({
    "name": "tokenLax",
    "value": TOKEN_COOKIE_LAX,
    "domain": EXTERNAL_DOMAIN,
    "path": "/",
    "secure": False,
    "httpOnly": False,
    "sameSite": "Lax"
})

driver.add_cookie({
    "name": "tokenSecure",
    "value": TOKEN_COOKIE_STRICT,
    "domain": EXTERNAL_DOMAIN,
    "path": "/",
    "secure": False,
    "httpOnly": False,
    "sameSite": "Strict"
})

# driver.execute_script(f'document.cookie = "token={TOKEN_COOKIE}; path=/; ";')

logging.info(f"Injected cross-site cookie for {EXTERNAL_DOMAIN}: ")
logging.info(driver.get_cookies())

proc.terminate()
proc.wait()
logging.info("Stopped spoofed HTTP server.")

logging.info(f"Starting DNS retriever for {EXTERNAL_DOMAIN}.")
start_dns_watch(EXTERNAL_DOMAIN, DNS_SERVER)

# Selenium watches for the element to be ready
wait = WebDriverWait(driver, 2)  # 2 second cap

# Now loop over requesting TARGET_URL that they will arpspoof
try:
    while True:
        try:
            host = str(urlparse(TARGET_URL).hostname)
            logging.info(f"Visiting {TARGET_URL} ({socket.gethostbyname(host)} @ {get_mac_for_ip(socket.gethostbyname(host))})...")
            driver.get(TARGET_URL)
            time.sleep(2)

            try:
                textarea = wait.until(EC.presence_of_element_located((By.ID, "notes")))
                
                send = f"{TOKEN_TYPING}" + "\n1. Bananas\n2.Banaanananana\n3. Banana?\n"
                
                textarea.send_keys(send)
                logging.info(f"Typed flag into note: {TOKEN_TYPING}")
            except TimeoutException:
                logging.warning("Note input not found within timeout window.")
        except WebDriverException as e:
            if "ERR_CONNECTION_REFUSED" in str(e):
                logging.warning(f"Connection refused while trying to reach {TARGET_URL}, this is likely safe, due to competitor attacking.")
            else:
                logging.warning(f"{e}")
        except Exception as e:
            logging.warning(f"{e}")
        time.sleep(10)  # Give JS time to exfiltrate
finally:
    driver.quit()

