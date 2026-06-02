#!/usr/bin/env python3
import socket, os, json, time, secrets, threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
SOCKET = __import__('sys').argv[1] if len(__import__('sys').argv)>1 else "/tmp/crypto.sock"
KEYFILE='/opt/elitebox/data/priv.pem'
PUBFILE='/opt/elitebox/data/pub.pem'
LOGFILE='/opt/elitebox/data/oracle.log'

# generate key if missing
if not os.path.exists(KEYFILE):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEYFILE,'wb') as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
    with open(PUBFILE,'wb') as f:
        f.write(key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
else:
    from cryptography.hazmat.primitives import serialization as s2
    with open(KEYFILE,'rb') as f:
        key = s2.load_pem_private_key(f.read(), password=None)

# socket
if os.path.exists(SOCKET): os.unlink(SOCKET)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(SOCKET)
os.chmod(SOCKET, 0o660)
s.listen(4)

# naive per-client rate limiting stored in memory
_last = {}

def allowed(client_id):
    now = time.time()
    data = _last.get(client_id, [])
    # allow only 30 queries per hour
    window = 3600
    data = [t for t in data if now - t < window]
    if len(data) >= 30:
        return False
    data.append(now)
    _last[client_id] = data
    return True

def handle(c):
    try:
        data = c.recv(8192)
        if not data:
            return
        try:
            j = json.loads(data.decode())
        except:
            c.send(b'{"error":"bad json"}'); return
        # restrict clients to local uid - we enforce via socket perms, but also check nothing else here
        client = c.getpeername() if hasattr(c,'getpeername') else 'local'
        if not allowed(client):
            c.send(b'{"error":"rate"}'); return
        cmd=j.get("cmd","")
        if cmd=="getpub":
            with open(PUBFILE,'rb') as f: c.send(f.read()); return
        if cmd=="decrypt":
            # very constrained oracle: decrypt and reply a single bit about whether the first 2 bytes are 0x00 0x01
            try:
                ct=bytes.fromhex(j.get("ct",""))
            except:
                c.send(b'{"error":"badct"}'); return
            try:
                pt = key.decrypt(ct, padding.PKCS1v15())
            except Exception:
                c.send(b'{"error":"decfail"}'); return
            # log minimal info
            with open(LOGFILE,'a') as L: L.write(f"{time.time()} {len(ct)} {len(pt)}\n")
            if len(pt)>=2 and pt[0]==0x00 and pt[1]==0x01:
                c.send(b'{"ok":true,"bit":1}')
            else:
                c.send(b'{"ok":true,"bit":0}')
            return
        c.send(b'{"error":"unknown"}')
    finally:
        try: c.close()
        except: pass

while True:
    conn,_ = s.accept()
    t=threading.Thread(target=handle,args=(conn,),daemon=True); t.start()
