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
