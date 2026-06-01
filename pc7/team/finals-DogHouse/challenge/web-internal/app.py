import os
import urllib.parse
import traceback
from flask import Flask, request, render_template_string, session, redirect, url_for
from ldap3 import Server, Connection, ALL, SUBTREE

app = Flask(__name__)

# === Config ===
LDAP_URL = os.environ["LDAP_URL"]
LDAP_BIND = os.environ["LDAP_BIND"]
LDAP_PW = os.environ["LDAP_PW"]
LDAP_BASE = os.environ["LDAP_BASE"]
USERS_GID = os.environ["USERS_GID"]
ADMIN_GID = os.environ["ADMIN_GID"]
ADMIN_UID = os.environ["ADMIN_UID"]

UI_SECRET  = os.getenv("UI_SECRET", "d4f4f56447119f27c245a453d5162adf")
LDAP_BASE  = os.getenv("LDAP_BASE", "dc=ctf,dc=local")
app.secret_key = UI_SECRET

# === Navbar (shared) ===
NAVBAR_HTML = """
<style>
.navbar {
  background-color: #333;
  overflow: hidden;
  margin: -18px -18px 18px -18px;
  padding-left: 18px;
}
.navbar a {
  float: left;
  color: #f2f2f2;
  text-align: center;
  padding: 12px 16px;
  text-decoration: none;
  font-size: 17px;
}
.navbar a:hover {
  background-color: #ddd;
  color: black;
}
.navbar a.active {
  background-color: #04AA6D;
  color: white;
}
.navbar a.logout {
  float: right;
}
</style>

<div class="navbar">
  <a href="/" class="{{ 'active' if active=='helpdesk' else '' }}">Helpdesk</a>
  <a href="/search" class="{{ 'active' if active=='search' else '' }}">Search</a>
  <a href="/logout" class="logout">Logout</a>
</div>
"""

LOGIN_HTML = """
<!doctype html>
<title>Employee Web Login</title>
<h2>Employee Web Login</h2>
<form method="post" action="/login">
  <input name="u" placeholder="username" autofocus>
  <input name="p" type="password" placeholder="password">
  <button>Login</button>
</form>
{% if error %}<p style="color:#b00">{{ error }}</p>{% endif %}
"""

HELPDESK_HTML = """
<!doctype html>
<title>Helpdesk</title>
""" + NAVBAR_HTML + """
<style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 18px; color: #222; }
    h2 { margin-bottom: 6px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 18px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #e6e6e6; }
    th { background: #f7f7f7; color: #333; font-weight: 600; }
    .badge { display:inline-block; padding:3px 8px; border-radius:12px; font-size:12px; color:#fff; }
    .assigned { background:#e67e22; }  /* orange */
    .inprogress { background:#f1c40f; color:#111; } /* yellow */
    .available { background:#27ae60; } /* green */
    .unassigned { background:#7f8c8d; } /* gray */
    .meta { color:#666; font-size:12px; margin-bottom:12px; }
</style>

<h2>Helpdesk — Open Tickets</h2>
<div class="meta">Internal view — employees only. Last update: 2026-03-03 10:25 UTC</div>

<table>
    <thead>
    <tr><th>ID</th><th>Subject</th><th>Submitted by</th><th>Assigned to</th><th>Status</th><th>Created</th></tr>
    </thead>
    <tbody>
    <tr>
        <td>TCK-1042</td>
        <td>Backup job J-1142 stuck in queued state</td>
        <td>rjones@ctf.local</td>
        <td>ajennings</td>
        <td><span class="badge assigned">Assigned</span></td>
        <td>2026-03-01 09:32</td>
    </tr>
    <tr>
        <td>TCK-1043</td>
        <td>Restore portal 502 error</td>
        <td>ajennings@ctf.local</td>
        <td>—</td>
        <td><span class="badge unassigned">Unassigned</span></td>
        <td>2026-03-02 13:47</td>
    </tr>
    <tr>
        <td>TCK-1044</td>
        <td>New client onboarding request DS-2026-03</td>
        <td>rjones@ctf.local</td>
        <td>esmith</td>
        <td><span class="badge inprogress">In Progress</span></td>
        <td>2026-03-02 14:12</td>
    </tr>
    </tbody>
</table>

<h2>Employee Status</h2>
<table>
    <thead>
    <tr><th>Employee</th><th>Role</th><th>Current ticket</th><th>Status</th></tr>
    </thead>
    <tbody>
    <tr>
        <td>ajennings</td>
        <td>Storage Architect</td>
        <td>TCK-1042</td>
        <td><span class="badge assigned">Assigned</span></td>
    </tr>
    <tr>
        <td>jwilliams</td>
        <td>Ops Engineer</td>
        <td>TCK-1044</td>
        <td><span class="badge assigned">Assigned</span></td>
    </tr>
    <tr>
        <td>rjones</td>
        <td>Manager</td>
        <td>—</td>
        <td><span class="badge available">Available</span></td>
    </tr>
    <tr>
        <td>esmith</td>
        <td>Support Tech</td>
        <td>—</td>
        <td><span class="badge available">Available</span></td>
    </tr>
    </tbody>
</table>
"""

SEARCH_HTML = """
<!doctype html>
<title>User Search</title>
""" + NAVBAR_HTML + """
<h2>Employee Lookup</h2>
<form action="/search" method="get">
  Search attribute:
    <select name="attr">
      <option value="uid">uid</option>
      <option value="cn">cn</option>
      <option value="mail">mail</option>
    </select>
  UID: <input name="user" size="80"/>
  <input type="submit" value="Search">
</form>

<pre>{{ result }}</pre>
"""

@app.before_request
def _require_login():
    allowed = {"login", "logout", "static"}
    if request.endpoint in allowed:
        return
    if not session.get("u"):
        return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("u"):
            return redirect(url_for("index"))
        return render_template_string(LOGIN_HTML, error=None)
    u = (request.form.get("u") or "").strip()
    p = request.form.get("p") or ""
    if not u or not p:
        return render_template_string(LOGIN_HTML, error="username and password required"), 400
    try:
        srv = Server(LDAP_URL)
        user_dn = f"uid={u},ou=people,{LDAP_BASE}"
        with Connection(srv, user=user_dn, password=p, auto_bind=True):
            session["u"] = u
            return redirect(url_for("index"))
    except Exception:
        return render_template_string(LOGIN_HTML, error="invalid credentials"), 403

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def index():
    return render_template_string(HELPDESK_HTML, active="helpdesk")

def build_vulnerable_uid_filter(final_userval, users_gid):
    return "(|(&(%s=%s)(gidNumber=%s)))" % ("uid", final_userval, USERS_GID)

@app.route("/search")
def search():
    has_query = bool(request.args)
    if not has_query:
        return render_template_string(SEARCH_HTML, active="search", result="")

    attr = request.args.get("attr", "uid").strip()
    val_after_flask = request.args.get("user", "")

    sanitized_after_flask = val_after_flask.replace("(", "").replace(")", "")
    try:
        final_userval = urllib.parse.unquote_plus(sanitized_after_flask)
    except Exception:
        final_userval = sanitized_after_flask

    ldap_filter = build_vulnerable_uid_filter(final_userval, USERS_GID)

    requested_attrs = [attr]
    if "gidNumber" not in requested_attrs:
        requested_attrs.append("gidNumber")

    server = Server(LDAP_URL, get_info=ALL)
    try:
        conn = Connection(server, user=LDAP_BIND, password=LDAP_PW, auto_bind=True)
    except Exception as e:
        final_output = f"LDAP bind failed: {e}\n\nConstructed filter: {ldap_filter}"
        return render_template_string(SEARCH_HTML, active="search", result=final_output)

    try:
        conn.search(search_base=LDAP_BASE,
                    search_filter=ldap_filter,
                    search_scope=SUBTREE,
                    attributes=requested_attrs)
    except Exception as e:
        conn.unbind()
        final_output = f"LDAP error: {e}\n\nConstructed filter: {ldap_filter}"
        return render_template_string(SEARCH_HTML, active="search", result=final_output)

    results = []
    for entry in conn.entries:
        attrs_dict = entry.entry_attributes_as_dict

        gid_val = attrs_dict.get("gidNumber", [])
        if isinstance(gid_val, list):
            gids_list = [str(x) for x in gid_val]
        else:
            gids_list = [str(gid_val)]
        uid_val = attrs_dict.get("uid") or attrs_dict.get("cn")
        is_admin = (
            (ADMIN_GID and str(ADMIN_GID) in gids_list) or
            (ADMIN_UID and uid_val and str(uid_val).lower() == str(ADMIN_UID).lower())
        )
        if is_admin:
            continue

        val = attrs_dict.get(attr)
        results.append({attr: val})

    conn.unbind()

    def to_display_string(value):
        """Returns a safe string for a single value (bytes/list/str/other)."""
        if isinstance(value, list):
            value = value[0] if value else ""
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8", errors="replace")
            except Exception:
                return repr(value)
        return str(value)

    lines = []
    for r in results:
        for k, v in r.items():
            lines.append(f"{k}: {to_display_string(v)}")
    pretty_results = "\n".join(lines) if lines else "(no results found)"
    final_output = f"{pretty_results}\n\n\nInput decoded and stripped...\n\nConstructed filter: {ldap_filter}"
    return render_template_string(SEARCH_HTML, active="search", result=final_output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
