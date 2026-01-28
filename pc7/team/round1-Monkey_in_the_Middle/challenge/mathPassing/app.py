import ipaddress
import socket
import os
import time
import logging
import hmac
import hashlib
import random
import re
import sys
import uuid
import fcntl
import struct
import subprocess

# Logging setup
logging.basicConfig(
    format='%(asctime)s | %(levelname)s | %(message)s',
    level=logging.INFO
)

# Environment config
ROLE = os.getenv("ROLE")
HOST = os.getenv("HOST")

if not HOST:
    logging.error("Missing required environment variable HOST.")
    sys.exit(1)

while True:
    if HOST == "0.0.0.0":  # Server specifies listening IP address
        break  
    try:
        info = socket.getaddrinfo(HOST, None, socket.AF_INET)
        if info:
            HOST = info[0][4][0]  # resolved IP
            break
    except socket.gaierror as e:
        logging.warning(f"Resolution error for {HOST}: {e}")

    logging.warning(f"Failed to resolve {HOST}; retrying in 5 seconds...")
    time.sleep(5)
        
PORT = os.getenv("PORT")
SHARED_KEY = os.getenv("KEY")
EAVESDROP_TOKEN = os.getenv("eavesdropToken")
MATH_TOKEN = os.getenv("mathToken")

# Log all values including MAC address
mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(40, -8, -8)])
logging.info(f"ROLE={ROLE}, HOST={HOST}, PORT={PORT}, KEY={SHARED_KEY}, MAC={mac}, EAVESDROP_TOKEN={EAVESDROP_TOKEN}, MATH_TOKEN={MATH_TOKEN}")

if not ROLE or not HOST or not PORT or not SHARED_KEY or not EAVESDROP_TOKEN or not MATH_TOKEN:
    logging.error("Missing required environment variables.")
    sys.exit(1)

PORT = int(PORT)
BUFFER_SIZE = 2048
COUNT = 100
TIMEOUT = 10
NONCE_TIMEOUT = 5 # In milliseconds
MAX_OPERAND = 9999
OPERATORS = ["+", "-", "*"]
seen_nonces = set()

def generate_nonce() -> str:
    return str(int(time.time() * 1000))

def compute_ticket(nonce: str, key: str = SHARED_KEY, a: str = "", b: str = "") -> str:
    message = f"{nonce}:{a}:{b}"
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def evaluate_expression(expr: str) -> int:
    match = re.match(r"^(\d+)\s*([+\-*])\s*(\d+)$", expr.strip())
    if not match:
        raise ValueError("Invalid expression format")
    a, op, b = match.groups()
    a, b = int(a), int(b)
    if op == "+":
        return a + b
    elif op == "-":
        return a - b
    elif op == "*":
        return a * b
    raise ValueError("Unsupported operator")

def generate_expression() -> (str, int):
    a = random.randint(1, MAX_OPERAND)
    b = random.randint(1, MAX_OPERAND)
    op = random.choice(OPERATORS)
    result = evaluate_expression(f"{a}{op}{b}")
    return f"{a} {op} {b}", result

def wrap_message(expression: str, result: int | str) -> str:
    nonce = generate_nonce()
    match = re.match(r"^(\d+)\s*([+\-*])\s*(\d+)$", expression.strip())
    a, _, b = match.groups() if match else ("", "", "")
    ticket = compute_ticket(nonce, SHARED_KEY, a, b)
    return f"{ticket},{nonce},{expression} is {result}"

def verify(message: str) -> bool:
    try:
        ticket, nonce, expr = message.split(",", 2)
        if nonce in seen_nonces:
            logging.warning("[VERIFY] Nonce replay detected.")
            return False
        if abs(int(time.time() * 1000) - int(nonce)) > (NONCE_TIMEOUT * 1000):
            logging.warning("[VERIFY] Nonce too old or too new.")
            return False

        if " is " not in expr:
            logging.warning("[VERIFY] Invalid message format.")
            return False

        lhs, rhs = expr.rsplit(" is ", 1)
        match = re.match(r"^(\d+)\s*([+\-*])\s*(\d+)$", lhs.strip())
        if not match:
            logging.warning("[VERIFY] Could not extract operands")
            return False

        a, _, b = match.groups()
        expected = compute_ticket(nonce, SHARED_KEY, a, b)
        if ticket != expected:
            logging.warning("[VERIFY] HMAC mismatch.")
            return False

        if evaluate_expression(lhs.strip()) != int(rhs.strip()):
            logging.warning("[VERIFY] Math is incorrect.")
            return False

        seen_nonces.add(nonce)
        return True
    except Exception as e:
        logging.warning(f"[VERIFY] Error: {e}")
        return False

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

def server_handle(conn, addr):
    conn.settimeout(TIMEOUT)
    client_ip = addr[0]
    client_mac = get_mac_for_ip(client_ip)
    logging.info(f"[SERVER] Connection from {client_ip} (MAC: {client_mac})")

    data = conn.recv(BUFFER_SIZE)
    if not data:
        logging.warning("[SERVER] Did not receive first token")
        return

    message = data.decode()
    logging.info(f"[SERVER] Received: {message}")
    
    for i in range(COUNT):
        expr, correct = generate_expression()
        incorrect = correct
        while incorrect == correct:
            incorrect = random.randint(1, 9999)
        response = wrap_message(expr, incorrect)
        logging.info(f"[SERVER] Sending: {response}")
        conn.send(response.encode())
        
        data = conn.recv(BUFFER_SIZE)
        if not data:
            return

        message = data.decode()
        logging.info(f"[SERVER] Received: {message}")
        
        if not verify(message): 
            logging.info(f"[SERVER] Sending: INCORRECT")
            conn.send(b"INCORRECT")
            return

    logging.info("Finished math, sending token")
    response = f"Math Token: {MATH_TOKEN}"
    
    logging.info(f"[SERVER] Sending: {response}")
    conn.send(response.encode())

def run_server():
    global seen_nonces
    logging.info(f"Starting TCP server on {HOST}:{PORT}")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(1)
            while True:
                conn = None
                try:
                    conn, addr = s.accept()
                    server_handle(conn, addr)
                except Exception as e:
                    logging.warning(f"[SERVER] Error with connection: {e}")
                finally:
                    if conn is not None:
                        conn.close()
                    seen_nonces.clear()
                    time.sleep(NONCE_TIMEOUT)
    except Exception as e:
        logging.error(f"[SERVER] Server terminating: {e}") 
        
def run_client():
    global seen_nonces
    client_mac = get_mac_for_ip(HOST)
    logging.info(f"Starting TCP client to connect to {HOST}:{PORT} (MAC: {client_mac})")

    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((HOST, PORT))
        s.settimeout(TIMEOUT)
    except Exception as e:
        logging.info(f"[CLIENT] Error connecting, retrying: {e}")
        return

    try:
        logging.info("First message, sending token")
        message = f"Eavesdrop Token: {EAVESDROP_TOKEN}"
        
        logging.info(f"[CLIENT] Sending: {message}")
        s.send(message.encode())
        
        for i in range(COUNT):
            response = s.recv(BUFFER_SIZE)
            if not response:
                return

            response_text = response.decode()
            logging.info(f"[CLIENT] Received: {response_text}")

            if response_text == "INCORRECT" or not verify(response_text):
                s.send(b"INCORRECT")
                return
            expr, correct = generate_expression()
            incorrect = correct
            while incorrect == correct:
                incorrect = random.randint(1, 9999)
            message = wrap_message(expr, incorrect)
            
            logging.info(f"[CLIENT] Sending: {message}")
            s.send(message.encode())
         
        response = s.recv(BUFFER_SIZE)
        if not response:
            logging.warning("[CLIENT] Did not receive final token")
            return
        response_text = response.decode()
        logging.info(f"[CLIENT] Received: {response_text}")
    except Exception as e:
        logging.warning(f"[CLIENT] Connection failure: {e}")
    finally:
        s.close()
        logging.info("[CLIENT] Connection closed.")
        seen_nonces.clear()
        time.sleep(NONCE_TIMEOUT)

if ROLE == "server":
    run_server()
elif ROLE == "client":
    while True:
        time.sleep(2)  # Wait to make sure server is ready
        run_client()
else:
    logging.error(f"Unknown role: {ROLE}")
    sys.exit(1)
