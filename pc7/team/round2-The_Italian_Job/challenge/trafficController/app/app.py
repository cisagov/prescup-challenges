import threading
from flask import json, jsonify, render_template, Flask
import datetime
import logging

from simulator import start_traffic_simulator, LOCK
from panel import RINGS_PANEL, defaultPanel
import atexit
import time, logging, os
from flask import Flask
from flask_sock import Sock
from simple_websocket import ConnectionClosed

app = Flask(__name__)
sock = Sock(app)
logging.basicConfig(level=logging.INFO)

GRADING_URL = "grading_3c1e90a3b4e54fb1969e921a8df0f9cb"  # A secret rule that just returns the min times in json for easy grading; not an issue if discovered
CORRECT_PIN = os.getenv("TRAFFIC_PIN", "2614")

# Optional: tiny shared state for last key
def defaultState():
    return {"last_key": None, "last_ts": None, "currentPin": "", "login_state": ""} # login_state is either "", "incorrect", "correct"

STATE = defaultState()
CLIENTS = set()
CLIENTS_LOCK = threading.Lock()

CONFIG_TEMP = {"p1_min": 7, "p2_min": 10, "p3_min": 7,  "p4_min": 7,  "p5_min": 7,  "p6_min": 10, "p7_min": 7,  "p8_min": 7, 
               "p1_max": 25, "p2_max": 40, "p3_max": 25, "p4_max": 25, "p5_max": 25, "p6_max": 40, "p7_max": 25, "p8_max": 25}

# ---- simulator control helpers ----
_stop_sim = start_traffic_simulator(RINGS_PANEL)  # will hold the current simulator's stop() function

def restart_simulator():
    """Stop current simulator (if any), reset panel, start a new one."""
    global _stop_sim, RINGS_PANEL, STATE
    # Stop old thread
    try:
        if _stop_sim:
            _stop_sim()
    except Exception as e:
        logging.warning("Error stopping simulator: %s", e, exc_info=True)

    # Reset panel to defaults
    with LOCK:
        RINGS_PANEL = defaultPanel()  # brand new dict with ring/ped fields
        STATE = defaultState()

    # Start new thread on the new dict
    _stop_sim = start_traffic_simulator(RINGS_PANEL)

def getPage():
    with LOCK:
        return RINGS_PANEL["page"]

def build_panel_text():
    with LOCK:
        if RINGS_PANEL["page"] == "menu":
            return render_template("menu.html", **RINGS_PANEL)
        elif RINGS_PANEL["page"] == "login":
            return render_template("login.html", **RINGS_PANEL, entered = len(STATE["currentPin"]), login = STATE["login_state"].upper())
        elif RINGS_PANEL["page"] == "config":
            ctx = RINGS_PANEL | CONFIG_TEMP
            return render_template("config.html", **ctx)
        else:
            return render_template("status.html", **RINGS_PANEL)

def reset_temp():
    for key,_ in CONFIG_TEMP.items():
        CONFIG_TEMP[key] = RINGS_PANEL[key]

def save_temp():
    logging.info(f"Saving new min/max values: {CONFIG_TEMP}")
    for key,_ in CONFIG_TEMP.items():
        RINGS_PANEL[key] = CONFIG_TEMP[key]

def handle_keypress(key: str):
    """Map keypad inputs to actions. Example wiring below; customize freely."""
    with LOCK:
        STATE["last_key"] = key
        STATE["last_ts"] = time.time()
        
        if key == "MENU":
            if RINGS_PANEL["page"] == "config":
                save_temp()
            RINGS_PANEL["page"] = "menu"   
            return
        
        if RINGS_PANEL["page"] == "menu":
            if key == "1":
                RINGS_PANEL["page"] = "status"
            elif key == "2":
                STATE["currentPin"] = ""
                if RINGS_PANEL["panel_lock"] == "LOCKED":
                    logging.info("Redirected from config to login")
                    RINGS_PANEL["page"] = "login"
                else:
                    logging.info("Login successful, accessing config")
                    RINGS_PANEL["page"] = "config"
                    RINGS_PANEL["cursor"] = "min_1"
                    reset_temp()
        elif RINGS_PANEL["page"] == "status":
            if key == "2":
                # Simulate a ped button on the P2 side (northbound)
                RINGS_PANEL["pd2_calls"] = int(RINGS_PANEL.get("pd2_calls", 0) or 0) + 1
            elif key == "6":
                # Simulate a ped button on the P6 side (southbound)
                RINGS_PANEL["pd6_calls"] = int(RINGS_PANEL.get("pd6_calls", 0) or 0) + 1
        elif RINGS_PANEL["page"] == "config":
            if key in "1234567890":
                side, num = RINGS_PANEL["cursor"].split('_')
                val = str(CONFIG_TEMP[f"p{num}_{side}"])
                if len(val) >= 3:
                    val = ""
                val += key
                CONFIG_TEMP[f"p{num}_{side}"] = int(val)
            elif key == "ENTER":
                side, num = RINGS_PANEL["cursor"].split('_')
                num = int(num)
                if num >= 8:
                    if side == "min":
                        side = "max"
                    else:
                        side = "min"
                    num = 1
                else:
                    num = num + 1
                RINGS_PANEL["cursor"] = f"{side}_{num}"
                
        elif RINGS_PANEL["page"] == "login":
            if STATE["login_state"] == "incorrect":  # Reset number on any button press
                STATE["currentPin"] = ""
                STATE["login_state"] = ""
                return
            if STATE["login_state"] == "correct":  # Return to menu on any button press
                STATE["currentPin"] = ""
                STATE["login_state"] = ""
                RINGS_PANEL["page"] = "menu"
                return
            if key in "1234567890": # Handle PIN
                STATE["currentPin"] += key
                
                if len(STATE["currentPin"]) >= 4:
                    logging.info(f"Trying Pin {STATE["currentPin"]} (expecting {CORRECT_PIN})")
                    if STATE["currentPin"] == CORRECT_PIN:
                        logging.info("Pin correct, login successful")
                        RINGS_PANEL["panel_lock"] = "UNLOCKED"
                        STATE["login_state"] = "correct"
                    else:
                        logging.info("Bad Pin, no login")
                        STATE["login_state"] = "incorrect"

def broadcast(obj: dict):
    """Send a JSON message to all connected clients."""
    payload = json.dumps(obj)
    dead = []
    with CLIENTS_LOCK:
        for ws in list(CLIENTS):
            try:
                ws.send(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            CLIENTS.discard(ws)
            

def kill_ws_clients():
    """Force-close all connected WebSocket clients and zero the counter."""
    dead = []
    with CLIENTS_LOCK:
        for ws in list(CLIENTS):
            try:
                ws.close()  # simple-websocket: close without args
            except Exception as e:
                logging.warning("Error closing WS: %s", e, exc_info=True)
            finally:
                dead.append(ws)
        for ws in dead:
            CLIENTS.discard(ws)
        RINGS_PANEL["ws_clients"] = 0  # reflect immediately in panel

# WebSocket endpoint: streams the whole panel once per second
@sock.route("/ws")
def panel_ws(ws):
    with CLIENTS_LOCK:
        CLIENTS.add(ws)
        RINGS_PANEL["ws_clients"] = len(CLIENTS)
    logging.info("WS client connected")

    last_push = 0.0
    try:
        while True:
            # 1) Try to receive key events without blocking the stream
            try:
                msg = ws.receive(timeout=0.01)  # 10ms poll
            except TimeoutError:
                msg = None

            if msg:
                try:
                    data = json.loads(msg)
                except Exception:
                    data = None

                if isinstance(data, dict) and data.get("type") == "key":
                    key = str(data.get("key"))
                    handle_keypress(key)
                    # ACK to sender
                    try:
                        ws.send(json.dumps({"type": "ack", "key": key, "ok": True}))
                    except Exception:
                        pass
                    # Optional broadcast so other clients can flash too
                    broadcast({"type": "key", "key": key, "src": "peer"})

            # 2) Push the full text panel
            now = time.time()
            if now - last_push >= 0.1:
                frame = build_panel_text()
                try:
                    ws.send(frame)
                except ConnectionClosed:
                    break
                last_push = now

    except Exception as e:
        logging.warning("WS loop error: %s", e, exc_info=True)
    finally:
        with CLIENTS_LOCK:
            CLIENTS.discard(ws)
            RINGS_PANEL["ws_clients"] = max(0, len(CLIENTS))
        logging.info("WS client disconnected")

@app.route("/reset", methods=["POST", "GET"])
def reset_controller():
    logging.info("Resetting! Dropping connections. May get a Connection Closed exception, can be ignored")
    # 1) kill sockets so clients drop immediately (JS will auto-reconnect)
    kill_ws_clients()

    # 2) stop & restart the simulator, and restore panel defaults
    logging.info("Stopping thread and restoring all defaults")
    restart_simulator()

    logging.info("Reset successful")

    return {"ok": True, "event": "reset", "clients_killed": True}, 200

@app.get("/")
def panel():
    return render_template("panel.html", **RINGS_PANEL)

@app.route(f"/{GRADING_URL}", methods=["GET"])
def grading_min_times():
    with LOCK:
        mins = {str(n): int(RINGS_PANEL.get(f"p{n}_min", 0) or 0) for n in range(1, 9)}
    payload = {
        "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phases_min": mins
    }
    logging.info(f"Grading check got: {payload}")
    return jsonify(payload), 200

if __name__ == "__main__":
    atexit.register(_stop_sim)
    app.run(host="0.0.0.0", port=80, debug=False)