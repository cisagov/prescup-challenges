#!/usr/bin/env python3
import os, tempfile, subprocess, json
from flask import Flask, request, session, redirect, url_for, render_template_string, send_file, abort
from ldap3 import Server, Connection, ALL, SUBTREE

LDAP_URL = os.environ["LDAP_URL"]
LDAP_BASE = os.environ["LDAP_BASE"]
LDAP_BIND = os.environ["LDAP_BIND"]
LDAP_PW = os.environ["LDAP_PW"]

UI_SECRET  = os.getenv("UI_SECRET", "d4f4f56447119f27c245a453d5162adf")
CA_CONF    = os.getenv("CA_CONF",   "/etc/ssl/openssl.cnf")
CA_DIR     = os.getenv("CA_DIR",    "/ca")
CA_CERT    = os.getenv("CA_CERT",   f"{CA_DIR}/cacert.pem")
CA_KEY     = os.getenv("CA_KEY",    f"{CA_DIR}/cakey.pem")
CA_EXT_DEFAULT = os.getenv("CA_EXT_DEFAULT", "/etc/ssl/extensions.client")
SIGN_DAYS  = int(os.getenv("SIGN_DAYS", "365"))
KRB_REALM  = os.getenv("KRB_REALM", "CTF.LOCAL")

app = Flask(__name__)
app.secret_key = UI_SECRET

INDEX = """
<!doctype html><title>CTF CA</title>
<h2>CA Login</h2>
<form method=post action="/login">
  <input name=u placeholder="username">
  <input name=p type=password placeholder="password">
  <button>Login</button>
</form>
<hr>
{% if session.get('u') %}
  <p>Logged in as <b>{{session['u']}}</b> (group: <b>{{session['g']}}</b>)</p>
  <h3>Request a Client Certificate</h3>
  <form method=post action="/sign" enctype="multipart/form-data">
    <p><b>Step 1:</b> Upload your CSR (PEM):</p>
    <input type=file name=csr accept=".csr,.pem,.req" required>
    <p style="margin-top:1em;"><b>Step 2 (optional):</b> Upload a custom OpenSSL extensions file (used as <code>-extfile</code>).<br>
    <small>Only allowed for <i>admins</i> and <i>causers</i>. If omitted, the default server extensions will be used.</small></p>
    <input type=file name=extfile accept=".cnf,.conf,.txt">
    <div style="margin-top:1em;">
      <button>Request Sign</button>
    </div>
  </form>
  <p><a href="/logout">Logout</a></p>
{% endif %}
"""

def _ldap_groups_for(uid: str):
    # groupOfNames membership
    srv = Server(LDAP_URL, get_info=ALL)
    with Connection(srv, LDAP_BIND, LDAP_PW, auto_bind=True) as c:
        c.search(LDAP_BASE, f"(uid={uid})", attributes=['uid'], search_scope=SUBTREE)
        if not c.entries: return []
        dn = c.entries[0].entry_dn
        c.search(LDAP_BASE,
                 f"(|(member={dn})(uniqueMember={dn})(memberUid={uid}))",
                 search_scope=SUBTREE, attributes=['cn'])
        return [e.cn.value for e in c.entries]

def _ldap_groups_for(uid: str):
    # groupOfNames membership
    srv = Server(LDAP_URL, get_info=ALL)
    with Connection(srv, LDAP_BIND, LDAP_PW, auto_bind=True) as c:
        c.search(LDAP_BASE, f"(uid={uid})", attributes=['uid'], search_scope=SUBTREE)
        if not c.entries: return []
        dn = c.entries[0].entry_dn
        c.search(LDAP_BASE,
                 f"(|(member={dn})(uniqueMember={dn})(memberUid={uid}))",
                 search_scope=SUBTREE, attributes=['cn'])
        return [e.cn.value for e in c.entries]

def _parse_csr_sans(csr_pem: str):
    # Parse SANs using openssl text output
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
        f.write(csr_pem); path = f.name
    out = subprocess.check_output(["openssl","req","-in",path,"-noout","-text"], text=True, stderr=subprocess.STDOUT)
    os.unlink(path)
    san_block = []
    grab = False
    for line in out.splitlines():
        if "Subject Alternative Name" in line:
            grab = True
            continue
        if grab:
            if line.strip().startswith("Signature Algorithm"): break
            san_block.append(line.strip())
    joined = " ".join(san_block)
    # crude checks
    has_upn = ("othername:" in joined.lower()) or ("otherName:" in joined)
    return joined, has_upn

@app.route("/", methods=["GET"])
def root():
    return render_template_string(INDEX)

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("u","").strip()
    p = request.form.get("p","")
    srv = Server(LDAP_URL)
    user_dn = f"uid={u},ou=people,{LDAP_BASE}"
    ok = False
    try:
        with Connection(srv, user_dn, p, auto_bind=True) as _:
            ok = True
    except Exception:
        ok = False
    if not ok:
        return "invalid credentials", 403
    groups = _ldap_groups_for(u)
    # pick first match in priority
    g = "users"
    for cand in ("admins","causers","users"):
        if cand in groups:
            g = cand; break
    session['u'] = u
    session['g'] = g
    return redirect(url_for("root"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("root"))


@app.route("/sign", methods=["POST"])
def sign():
    if 'u' not in session: 
        return redirect(url_for("root"))
    csr = request.files.get("csr")
    if not csr: 
        return "no csr", 400
    csr_pem = csr.read().decode("utf-8", errors="ignore")

    # policy by group
    joined, has_upn = _parse_csr_sans(csr_pem)
    g = session['g']
    u = session['u']
    extfile = request.files.get("extfile")

    if g == "users":
        if has_upn:
            return "users policy forbids UPN (otherName 1.3.6.1.5.2.2) SAN", 400
        if extfile and extfile.filename:
            return "users policy forbids custom extensions", 400

    import tempfile, os, subprocess

    # Write CSR to a temp file
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(csr_pem)
        csr_path = f.name
    out_path = csr_path + ".pem"

    # Prepare env for openssl
    env = os.environ.copy()
    env["REALM"] = KRB_REALM
    env["CLIENT"] = u

    # Determine extfile path
    extfile_path = None
    try:
        if extfile and extfile.filename and g in ("admins","causers"):
            data = extfile.read().decode("utf-8", errors="ignore")
            with tempfile.NamedTemporaryFile(delete=False, mode="w") as ef:
                ef.write(data)
                extfile_path = ef.name
        else:
            if os.path.exists(CA_EXT_DEFAULT):
                extfile_path = CA_EXT_DEFAULT

        cmd = [
            "openssl","x509",
            "-CAkey", CA_KEY,
            "-CA", CA_CERT,
            "-req","-in", csr_path,
            "-days", str(SIGN_DAYS),
            "-out", out_path,
        ]
        if extfile_path:
            cmd.extend(["-extensions","client_cert","-extfile", extfile_path])

        proc = subprocess.run(cmd, cwd=CA_DIR, env=env, capture_output=True, text=True)
        if proc.returncode != 0 or not os.path.exists(out_path):
            err = (proc.stderr or proc.stdout or "").strip()
            return f"sign failed: {err}", 500

        return send_file(out_path, as_attachment=True, download_name="cert.pem")
    finally:
        try: os.unlink(csr_path)
        except Exception: pass
        try:
            if out_path and os.path.exists(out_path):
                os.unlink(out_path)
        except Exception: pass
        try:
            if extfile_path and os.path.exists(extfile_path) and extfile_path != CA_EXT_DEFAULT:
                os.unlink(extfile_path)
        except Exception: pass

if __name__ == "__main__":
    os.makedirs(f"{CA_DIR}/newcerts", exist_ok=True)
    app.run(host="0.0.0.0", port=80)
