import socket, threading

OT_IP = "ot_ip"     # replace at runtime
LISTEN_PORT = 5020

PLC_IP = "plc_ip"    # replace at runtime
PLC_PORT = 5020

def pump(src, dst):
    try:
        while True:
            data = src.recv(65535)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass

def handle_client(c, addr):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Force outbound source IP to OT_IP (important part)
        s.bind((OT_IP, 0))
        s.connect((PLC_IP, PLC_PORT))

        t1 = threading.Thread(target=pump, args=(c, s), daemon=True)
        t2 = threading.Thread(target=pump, args=(s, c), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
    finally:
        try: c.close()
        except: pass
        try: s.close()
        except: pass

ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind((OT_IP, LISTEN_PORT))
ls.listen(50)
print(f"[helper] listening on {OT_IP}:{LISTEN_PORT} -> {PLC_IP}:{PLC_PORT}")

while True:
    c, addr = ls.accept()
    threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()