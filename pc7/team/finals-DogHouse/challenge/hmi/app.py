#!/usr/bin/env python3
import os, time
from flask import Flask, jsonify, Response
from pymodbus.client import ModbusTcpClient

TOKEN4 = os.environ["TOKEN4"]
PLC_HOST = "plc"
PLC_PORT = 5020
UNIT_ID  = 1

# Register map
REG_TANK_LEVEL = 10  # HR[10]  
REG_PUMP_STATE = 11  # HR[11]  0/1
REG_FILL_LIMIT = 20  # HR[20] 
REG_VALVE  = 21  # HR[21]  
REG_FLOOD      = 30  # HR[30]  0/1
REG_TOKEN_FLAG = 31  # HR[31]

app = Flask(__name__)

def read_hr(addr, count=1):
    """Read holding registers; return list[int] or None on error."""
    c = ModbusTcpClient(PLC_HOST, port=PLC_PORT)
    if not c.connect():
        return None
    try:
        rr = c.read_holding_registers(addr, count, unit=UNIT_ID)
        if hasattr(rr, "isError") and rr.isError():
            return None
        return list(rr.registers)
    except Exception:
        return None
    finally:
        c.close()

def snapshot():
    tank = read_hr(REG_TANK_LEVEL, 1)
    pump = read_hr(REG_PUMP_STATE, 1)
    limit = read_hr(REG_FILL_LIMIT, 1)
    valve= read_hr(REG_VALVE, 1)
    flood= read_hr(REG_FLOOD, 1)
    token_flag = read_hr(REG_TOKEN_FLAG, 1)
    token_text = TOKEN4 if (token_flag and token_flag[0] == 1) else None
    data = {
        "plc_host": PLC_HOST,
        "plc_port": PLC_PORT,
        "unit_id": UNIT_ID,
        "tank_percent": (tank[0] if tank else None),
        "pump_state":   (pump[0] if pump else None),
        "fill_limit":       (limit[0] if limit else None),
        "valve":    (valve[0] if valve else None),
        "flood":        (flood[0] if flood else None),
        "token":        token_text,
        "ts": int(time.time())
    }
    return data

@app.get("/status")
def status():
    return jsonify(snapshot())

@app.get("/raw")
def raw():
    s = snapshot()
    txt = "\n".join(f"{k}: {v}" for k,v in s.items())
    return Response(txt + "\n", mimetype="text/plain")

@app.get("/")
def home():
    # poll status every second
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>CTF HMI — Tank</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
  :root {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Inter, Arial; }}
  body {{ margin: 2rem; color: #0a0a0a; }}
  .row {{ display:flex; gap:2rem; align-items:flex-end; flex-wrap:wrap; }}
  .card {{ border:1px solid #e5e7eb; border-radius:12px; padding:1rem 1.25rem; box-shadow:0 1px 2px rgba(0,0,0,.04); }}
  .muted {{ color:#6b7280; font-size:.9rem; }}
  .tank {{
    position: relative; width: 160px; height: 260px;
    border: 2px solid #374151; border-radius: 10px; background: #f3f4f6; overflow: hidden;
  }}
  .water {{
    position: absolute; bottom: 0; left: 0; width: 100%;
    background: linear-gradient(180deg, #93c5fd, #60a5fa);
    transition: height .6s ease;
  }}
  .percent {{ position:absolute; top:8px; right:10px; font-weight:600; color:#111827; }}
  .label {{ margin-top:.5rem; text-align:center; font-weight:600; }}
  .badge {{ display:inline-block; padding:.25rem .5rem; border-radius:999px; font-size:.85rem; font-weight:600; }}
  .ok {{ background:#ecfdf5; color:#065f46; border:1px solid #a7f3d0; }}
  .warn {{ background:#fff7ed; color:#9a3412; border:1px solid #fed7aa; }}
  .danger {{ background:#fef2f2; color:#991b1b; border:1px solid #fecaca; }}
  .grid {{ display:grid; grid-template-columns: repeat(2, minmax(220px, 1fr)); gap:1rem; }}
  code {{ background:#f3f4f6; padding:.15rem .35rem; border-radius:6px; }}
</style>
</head>
<body>
  <h1>Water Tank Status</h1>
  <div id="tokenRow" style="display:none">
    Token: <strong id="token"></strong>
  </div>
  <div class="row">
    <div class="card">
      <div class="tank">
        <div id="water" class="water" style="height:20%"></div>
        <div id="percent" class="percent">20%</div>
      </div>
      <div class="label">Tank Level</div>
    </div>

    <div class="card">
      <div class="grid">
        <div>Fill Limit: <strong id="fill_limit">—</strong>%</div>
        <div>Pump: <span id="pump" class="badge ok">off</span></div>
        <div>Valve: <span id="valve" class="badge ok">closed</span></div>
        <div>Flood Alert: <span id="flood" class="badge ok">clear</span></div>
      </div>
    </div>
  </div>

<script>
async function poll() {{
  try {{
    const r = await fetch('/status', {{cache:'no-cache'}});
    const s = await r.json();

    const level = Math.max(0, Math.min(100, Number(s.tank_percent ?? 0)));
    const water = document.getElementById('water');
    const percent = document.getElementById('percent');
    water.style.height = level + '%';
    percent.textContent = level + '%';

    document.getElementById('fill_limit').textContent = s.fill_limit ?? '—';

    const pump = document.getElementById('pump');
    pump.textContent = (s.pump_state === 1) ? 'running' : 'off';
    pump.className = 'badge ' + ((s.pump_state === 1) ? 'warn' : 'ok');

    const valve = document.getElementById('valve');
    valve.textContent = (s.valve === 1) ? 'open' : 'closed';
    valve.className = 'badge ' + ((s.valve === 1) ? 'warn' : 'ok');

    const flood = document.getElementById('flood');
    const flooded = (s.flood === 1);
    flood.textContent = flooded ? 'FLOOD' : 'clear';
    flood.className = 'badge ' + (flooded ? 'danger' : 'ok');

    const tokenRow = document.getElementById('tokenRow');
    const token = document.getElementById('token');

    if (s.token) {{
      token.textContent = s.token;         // <-- use server-provided string
      tokenRow.style.display = 'block';    // reveal
    }} else {{
      token.textContent = '';
      tokenRow.style.display = 'none';     // keep invisible
    }}
    
  }} catch (e) {{
    console.error(e);
  }} finally {{
    setTimeout(poll, 1000);
  }}
}}
poll();
</script>
</body>
</html>"""
    return Response(html, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, threaded=True)
