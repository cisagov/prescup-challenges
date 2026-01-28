import os
import json
import time
import random
import threading
import socket
import sys
import paho.mqtt.client as mqtt

STATE_FILE = "state.json"
COORDINATES_FILE = "targets.txt"

# Challenge flags/tokens (set via env or fallback)
TOKEN1 = os.environ.get("token1")
TOKEN2 = os.environ.get("token2")
TOKEN3 = os.environ.get("token3")
TOKEN4 = os.environ.get("token4")
TOKEN5 = os.environ.get("token5")
TOKEN6 = os.environ.get("token6")

CHECKPOINT_TOPIC = "satellite/logs/checkpoints"
STATUS_TOPIC = "satellite/logs/status"

# Decoy topics
decoy_topics = [
    "satellite/control/diagnostics",
    "satellite/logs/thermal",
    "satellite/system/uptime",
    "satellite/comms/heartbeat",
    "satellite/security/auth",
    "satellite/control/orbit_sim",
    "satellite/logs/debug",
    "satellite/telemetry/battery",
    "satellite/update/firmware",
    "satellite/nav/vector",
    "satellite/ops/command_queue",
    "satellite/control/mode_legacy"
]

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def init_state():
    if not os.path.exists(STATE_FILE):
        angle = round(random.uniform(70.0, 95.0), 1)
        with open(COORDINATES_FILE, "r") as f:
            coords = f.readlines()
        coords = [line.strip() for line in coords if line.strip()]
        target_coord = "4.830,-73.950"
        state = {
            "mode": "observation",
            "coords": "N/A",
            "angle": "N/A",
            "hmac_ok": False,
            "target_angle": angle,
            "target_coord": target_coord,
            "token1_issued": False,
            "token2_issued": False,
            "token3_issued": False,
            "token4_issued": False,
            "token5_issued": False,
            "token6_issued": False
        }
        save_state(state)

def update_state_field(field, value):
    state = load_state()
    state[field] = value
    save_state(state)

def publish_final_flag(client):
    client.publish("satellite/logs/final", json.dumps({
        "event": "laser_fired",
        "token6": TOKEN6,
        "status": "mission_complete"
    }), retain=True)

def publish_coordinate_list(client):
    try:
        with open(COORDINATES_FILE, "r") as f:
            coords = f.read()
        client.publish("satellite/logs/telemetry_dump", coords)
    except Exception as e:
        client.publish(STATUS_TOPIC, f"⚠️ ERROR LOADING COORDINATES: {str(e)}")

def issue_checkpoint(client, token_name, flag, state):
    checkpoint_msg = f"✅ {token_name}: {flag}"
    client.publish(CHECKPOINT_TOPIC, checkpoint_msg)

def broadcast_topics(client):
    broadcast_list = [
        "[INFO] Uplink listener active on satellite/core/control",
        "[INFO] Payload monitor subscribed to satellite/control/fire",
        "[DEBUG] Diagnostic mode enabled — broadcasting on satellite/logs/status"
    ] + [f"[DEBUG] {topic} subscribed (system monitor)" for topic in decoy_topics]
    for log in broadcast_list:
        client.publish("satellite/logs/system", log)

def start_decoy_spammer(topic, client):
    def loop():
        while True:
            sleep_time = random.randint(10, 30)
            time.sleep(sleep_time)
            status = random.choices(["RULE", "WARN", "FAIL", "CRITICAL"], weights=[70, 15, 10, 5])[0]
            data = {
                "topic": topic,
                "status": status,
                "value": round(random.uniform(10.0, 120.0), 2),
                "timestamp": int(time.time())
            }
            if status == "CRITICAL" and "security" in topic:
                data["alert"] = "Unauthorized root process detected"
            elif status == "CRITICAL":
                data["alert"] = "Telemetry out-of-band threshold exceeded"
            client.publish(topic, json.dumps(data))
    threading.Thread(target=loop, daemon=True).start()

def start_hmac_beacon(client, topic="satellite/logs/hmac", hmac_val="g0ldeneye", interval=60):
    def beacon():
        while True:
            payload = {"hmac": hmac_val}
            client.publish(topic, json.dumps(payload))
            print(f"[HMAC VERIFICATION] Sent HMAC value '{hmac_val}' to {topic}")
            time.sleep(interval)
    threading.Thread(target=beacon, daemon=True).start()

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
    except Exception:
        client.publish(STATUS_TOPIC, "⚠️ Received invalid JSON payload.")
        return

    topic = msg.topic
    state = load_state()

    # TOKEN 1
    if (topic == "satellite/core/control" or topic.startswith("satellite/core/")) and not state.get("token1_issued"):
        issue_checkpoint(client, "TOKEN1", TOKEN1, state)
        state["token1_issued"] = True
        save_state(state)
        client.publish(STATUS_TOPIC, f"📥 Received message on `{topic}`: {payload}")

    # --- Mode --- TOKEN2
    if "mode" in payload:
        state["mode"] = payload["mode"]
        client.publish(STATUS_TOPIC, "📡 Mode updated: " + payload["mode"])
        if payload["mode"] == "attack" and not state.get("token2_issued"):
            client.publish(STATUS_TOPIC, "💥 ATTACK MODE ENABLED")
            issue_checkpoint(client, "TOKEN2", TOKEN2, state)
            state["token2_issued"] = True
        save_state(state)
        return

    # --- Angle ---
    CORRECT_ANGLE = 87.3
    if "angle" in payload:
        try:
            angle_val = float(payload["angle"])
        except Exception:
            angle_val = payload["angle"]
        state["angle"] = angle_val
        client.publish(STATUS_TOPIC, f"📐 Angle Updated: {angle_val}")
        if round(float(angle_val), 1) == CORRECT_ANGLE and not state.get("token3_issued"):
            client.publish(STATUS_TOPIC, f"✅ Correct Angle Detected: {angle_val}")
            issue_checkpoint(client, "TOKEN3", TOKEN3, state)
            state["token3_issued"] = True
        save_state(state)
        return

    # --- HMAC ---
    CORRECT_HMAC = "g0ldeneye"
    if "hmac" in payload:
        state["hmac_ok"] = payload["hmac"] == "g0ldeneye"
        client.publish(STATUS_TOPIC, f"🔐 HMAC updated: {payload['hmac']}")
        if payload["hmac"] == CORRECT_HMAC and not state.get("token4_issued"):
            state["hmac_ok"] = True
            client.publish(STATUS_TOPIC, f"🔓 HMAC Verified: {payload['hmac']}")
            issue_checkpoint(client, "TOKEN4", TOKEN4, state)
            state["token4_issued"] = True
        save_state(state)
        return

    # Coords
    if "coords" in payload:
        expected_coord = "4.830,-73.950"
        submitted_coords = str(payload["coords"])
        state["coords"] = submitted_coords
        client.publish(STATUS_TOPIC, f"🎯 Coordinates updated: {submitted_coords}")

        # (Optional: Remove after debugging)
        print(f"Checking if coords token should be issued: submitted='{submitted_coords}' expected='{expected_coord}' already_issued={state.get('token5_issued')} TOKEN5='{TOKEN5}'")

        if submitted_coords == expected_coord and not state.get("token5_issued"):
            client.publish(STATUS_TOPIC, f"✅ Correct coordinates detected.")
            issue_checkpoint(client, "TOKEN5", TOKEN5, state)
            state["token5_issued"] = True

        save_state(state)
        return

    # --- Command checks ---
    if payload.get("cmd") == "dump_coords":
        publish_coordinate_list(client)
        return

    if payload.get("cmd") and payload["cmd"] != "fire":
        client.publish(STATUS_TOPIC, "🛰️ COMMAND ERROR: Unsupported cmd type")
        return

    # --- Fire Command ---
    if payload.get("cmd") == "fire":
        required_fields = ("target", "angle", "hmac")
        if not all(k in payload for k in required_fields):
            client.publish(STATUS_TOPIC, "🔐 TRANSMISSION REJECTED: Missing telemetry fields")
            return

        expected_coord = state.get("target_coord")
        submitted_coord = payload["target"]
        submitted_angle = float(payload.get("angle"))
        submitted_hmac = payload.get("hmac")
        CORRECT_ANGLE = 87.3
        CORRECT_HMAC = "g0ldeneye"

        # Defensive: check for valid submitted_coord
        if not (isinstance(submitted_coord, dict) and "lat" in submitted_coord and "long" in submitted_coord):
            client.publish(STATUS_TOPIC, "❌ Invalid target format (should be a dict with lat/long)")
            return

        coord_string = f'{submitted_coord.get("lat")},{submitted_coord.get("long")}'

        # Check all at once:
        if (
            coord_string == expected_coord
            and round(submitted_angle, 1) == CORRECT_ANGLE
            and submitted_hmac == CORRECT_HMAC
        ):
            state.update({
                "coords": coord_string,
                "angle": submitted_angle,
                "hmac_ok": True,
                "mode": "attack"
            })
            client.publish(STATUS_TOPIC, "☢️☢️☢️ ORBITAL ALIGNMENT COMPLETE! ☢️☢️☢️")
            save_state(state)
            publish_final_flag(client)
            return

        # Otherwise, tell them what was wrong:
        if coord_string != expected_coord:
            client.publish(STATUS_TOPIC, "❌ Incorrect target coordinates")
        if round(submitted_angle, 1) != CORRECT_ANGLE:
            client.publish(STATUS_TOPIC, "❌ Incorrect angle")
        if submitted_hmac != CORRECT_HMAC:
            client.publish(STATUS_TOPIC, "❌ Incorrect HMAC")
        save_state(state)
        return

# -------------------------
# Broker readiness helpers
# -------------------------

def _resolve_ipv4(host: str) -> str:
    """Resolve host to an IPv4 address (first result)."""
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    return infos[0][4][0]

def wait_for_broker_ready(host: str, port: int, attempts: int, sleep_s: float) -> str:
    """
    Wait for DNS + TCP readiness and return resolved IPv4.
    Keeps the original 15-attempt style (configurable) and prints warnings like your current code.
    """
    last_err = None
    original_host = host

    for i in range(attempts):
        try:
            ip = _resolve_ipv4(original_host)
            # Ensure the port is actually accepting connections
            with socket.create_connection((ip, port), timeout=2):
                return ip
        except (socket.gaierror, OSError) as e:
            last_err = e
            print(f"[WARN] MQTT broker not ready, retrying in {sleep_s:.0f}s ({i+1}/{attempts}): {e}")
            time.sleep(sleep_s)

    print(f"[FATAL] Could not connect to MQTT broker after {attempts} attempts. Last error: {last_err}. Exiting.")
    sys.exit(1)

# --- Startup sequence ---

init_state()

# Allow env overrides without breaking existing defaults.
# Prefer MQTT_BROKER_HOST/PORT, then HOST/PORT, then defaults.
BROKER_HOST = os.getenv("MQTT_BROKER_HOST", os.getenv("HOST", "mqtt-broker"))
BROKER_PORT = int(os.getenv("MQTT_BROKER_PORT", os.getenv("PORT", "1883")))

CONNECT_ATTEMPTS = int(os.getenv("MQTT_CONNECT_ATTEMPTS", "15"))
CONNECT_SLEEP_S = float(os.getenv("MQTT_CONNECT_SLEEP", "2"))

client = mqtt.Client()  # keep your existing API usage
client.on_message = on_message

resolved_ip = wait_for_broker_ready(BROKER_HOST, BROKER_PORT, CONNECT_ATTEMPTS, CONNECT_SLEEP_S)

# Connect using the resolved IP (reduces reliance on DNS after startup).
client.connect(resolved_ip, BROKER_PORT, 60)

# Subscribe to all control/real and decoy topics
client.subscribe("satellite/core/control")
client.subscribe("satellite/control/fire")
for path in decoy_topics:
    client.subscribe(path)
    start_decoy_spammer(path, client)

broadcast_topics(client)
start_hmac_beacon(client, topic="satellite/logs/hmac")

client.loop_forever()