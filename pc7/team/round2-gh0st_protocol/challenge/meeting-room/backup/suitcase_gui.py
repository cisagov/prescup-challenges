from flask import Flask, request, render_template_string
import os, time, hashlib, json, urllib.request

app = Flask(__name__)

SESSION_ID = os.environ.get("SESSION_ID", "GHOSTSYNC-9321")
TOKEN4 = os.environ.get("TOKEN4", "flag{final_gui_validation}")
STATUS_URL = os.environ.get("STATUS_URL", "http://gh0st-protocol:8081/status")  # internal DNS

def session_ready():
    try:
        with urllib.request.urlopen(STATUS_URL, timeout=0.5) as r:
            data = json.loads(r.read().decode("utf-8"))
            return bool(data.get("ready"))
    except Exception:
        return False

HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Ghost Protocol // Secure Briefing Interface</title>
  <style>
    :root{--neon:#00ff9c;--bg:#02040a;--grid:#0b1b2a;--accent:#18ffff}
    *{box-sizing:border-box}body{background:radial-gradient(1200px 600px at 50% -10%,#061018 0%,var(--bg) 55%,#000 100%);color:var(--neon);font-family:"Share Tech Mono",Consolas,monospace;margin:0;padding:0;overflow:hidden}
    .crt:before{content:"";position:fixed;inset:0;pointer-events:none;background:repeating-linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.04) 1px,transparent 2px,transparent 3px);mix-blend-mode:overlay;opacity:.35}
    .wrap{position:relative;max-width:860px;margin:5vh auto;padding:28px;border:1px solid var(--neon);box-shadow:0 0 25px rgba(0,255,156,.25),inset 0 0 40px rgba(0,255,156,.08);border-radius:18px;background:linear-gradient(180deg,rgba(0,255,156,.05),rgba(0,0,0,.25))}
    .hud{display:grid;grid-template-columns:1fr auto;gap:16px;align-items:center;border-bottom:1px solid var(--neon);padding-bottom:16px;margin-bottom:18px}
    h1{margin:0;letter-spacing:2px;text-shadow:0 0 10px rgba(0,255,156,.5)}
    .pill{border:1px solid var(--neon);padding:6px 12px;border-radius:999px;font-size:.9rem;background:rgba(0,255,156,.08)}
    .grid{position:relative;border:1px solid var(--grid);border-radius:14px;padding:18px;background:linear-gradient(0deg,rgba(24,255,255,.05) 1px,transparent 1px) 0 0/100% 22px,linear-gradient(90deg,rgba(24,255,255,.05) 1px,transparent 1px) 0 0/22px 100%;box-shadow:inset 0 0 25px rgba(24,255,255,.08)}
    .status{display:flex;gap:12px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
    .dot{width:10px;height:10px;border-radius:50%;background:var(--accent);box-shadow:0 0 12px var(--accent)}.flash{animation:flash 1s infinite}
    @keyframes flash{0%{opacity:1}50%{opacity:.25}100%{opacity:1}}
    .row{display:flex;gap:12px;margin-top:14px;flex-wrap:wrap}
    input[type=text]{flex:1 1 380px;background:#000;color:var(--neon);border:1px solid var(--neon);padding:12px 14px;border-radius:12px;outline:none;font-size:1rem;box-shadow:inset 0 0 12px rgba(0,255,156,.15)}
    button{background:#000;color:var(--neon);border:1px solid var(--neon);padding:12px 18px;border-radius:12px;cursor:pointer;letter-spacing:1px;box-shadow:0 0 12px rgba(0,255,156,.3),inset 0 0 12px rgba(0,255,156,.08);transition:transform .08s ease}
    button:hover{transform:translateY(-1px)}.note{opacity:.85;font-size:.95rem}.ok{color:#7CFFB2}.err{color:#ff6b6b}
    .token{border:1px dashed var(--neon);padding:12px 14px;border-radius:10px;background:rgba(0,255,156,.05);display:inline-block}
    .ticker{font-size:.95rem;opacity:.9;display:flex;gap:12px;align-items:center}.badge{border:1px solid var(--neon);padding:4px 8px;border-radius:6px;font-size:.8rem}
  </style>
</head>
<body class="crt">
  <div class="wrap">
    <div class="hud">
      <h1>GHOST PROTOCOL — SECURE BRIEFING INTERFACE</h1>
      <div class="pill">
        {% if ready %}SESSION: <strong>{{session_id}}</strong>{% else %}SESSION: <strong>[LOCKED]</strong>{% endif %}
      </div>
    </div>

    {% if not validated %}
      <div class="grid">
        <div class="status">
          <div class="dot flash"></div>
          <div class="ticker"><span class="badge">SYNC</span>
            {% if ready %}Submit SHA256(SESSION_ID + current_epoch) within ±3s.{% else %}Ghost-sync not established. Complete the TCP phase first.{% endif %}
          </div>
        </div>

        <form method="POST" autocomplete="off">
          <div class="row">
            <input name="hash" type="text" placeholder="SHA256(SESSION_ID + current_epoch)" autofocus />
            <button type="submit">TRANSMIT</button>
          </div>
        </form>

        {% if message %}<p class="note {% if ok %}ok{% else %}err{% endif %}">{{message}}</p>{% endif %}
        <p class="note">Prepare your script, then fire.</p>
      </div>
    {% else %}
      <div class="grid">
        <div class="status"><div class="dot"></div>
        <div class="ticker"><span class="badge">SYNC</span> Window accepted. Identity verified.</div></div>
        <p class="note ok">Decryption channel open. Final payload unlocked:</p>
        <p class="token">✅ TOKEN4: {{token4}}</p>
        <p class="note ok"> ☢️ If you're seeing this, you have verified the NUCLEAR CODES. Your mission doesn't end here, Mr. Hunt.</p>
      </div>
    {% endif %}
  </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def gui():
    ready = session_ready()
    validated = False
    message, ok, token4 = "", False, None

    if request.method == "POST":
        user_hash = (request.form.get("hash") or "").strip().lower()
        now = int(time.time())
        for offset in range(-3, 4):
            epoch = str(now + offset)
            want = hashlib.sha256((SESSION_ID + epoch).encode()).hexdigest()
            if user_hash == want:
                validated, ok, token4 = True, True, TOKEN4
                break
        if not validated:
            message = "❌ Invalid sync hash or timing window missed. Recompute and retransmit."

    return render_template_string(
        HTML,
        ready=ready,
        session_id=SESSION_ID,
        validated=validated,
        message=message,
        ok=ok,
        token4=token4,
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

