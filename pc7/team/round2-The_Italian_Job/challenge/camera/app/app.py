#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ONVIF camera simulator (SOAP 1.2)

Endpoints:
  GET  /about
  POST /onvif/device_service   (SOAP 1.2)
  POST /onvif/media            (SOAP 1.2)
  POST /onvif/ptz              (SOAP 1.2)
  GET  /snapshot               (JPEG; requires auth)

Highlights:
  - Pre-generated frames in ./images/security_cam_*.jpg
  - Timestamp overlay on snapshots
  - PTZ panning via tptz:ContinuousMove (PanTilt@x)
  - Deliberate vuln: Device.GetSystemBackup allowed WITHOUT auth and contains leaked creds (base64 XML)

Run:
  pip install flask pillow
  python app.py
"""

from flask import Flask, request, Response, jsonify
from functools import wraps
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import base64
import datetime
import glob
import os
import threading
import xml.etree.ElementTree as ET

app = Flask(__name__)

# ------------------------------
# Config (intended leakage)
# ------------------------------
ADMIN_USER = os.environ.get("CAM_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("CAM_ADMIN_PASS", "Admin!2025")

IMAGE_GLOB = os.environ.get("CAM_IMAGE_GLOB", "images/security_cam_*.jpg")

# ------------------------------
# State
# ------------------------------
PTZ_LOCK = threading.RLock()
PTZ_INDEX = 0
IMAGES = sorted(glob.glob(IMAGE_GLOB))

# Prepare a placeholder if no images found
PLACEHOLDER_BYTES = None
if not IMAGES:
    img = Image.new("RGB", (960, 540), (20, 20, 20))
    d = ImageDraw.Draw(img)
    d.text((20, 20), "No images found (using placeholder)", fill=(230, 230, 230), font=ImageFont.load_default())
    bio = BytesIO()
    img.save(bio, format="JPEG", quality=85)
    PLACEHOLDER_BYTES = bio.getvalue()
    IMAGES = ["__placeholder__"]

def clamp_index(i: int) -> int:
    return max(0, min(i, len(IMAGES) - 1))

def host_base() -> str:
    # e.g. "http://127.0.0.1:8081/"
    return request.host_url

# ------------------------------
# Auth
# ------------------------------
def valid_creds(user: str, pwd: str) -> bool:
    return (user == ADMIN_USER and pwd == ADMIN_PASS)

def require_basic_auth(realm="ONVIF"):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            auth = request.authorization
            if not auth or not valid_creds(auth.username, auth.password):
                return Response("Authentication required", 401, {"WWW-Authenticate": f'Basic realm="{realm}"'})
            return fn(*args, **kwargs)
        return wrapped
    return deco

# ------------------------------
# Imaging
# ------------------------------
def snapshot_bytes(idx: int) -> bytes:
    """
    Render the current frame (based on idx) with a timestamp overlay and return JPEG bytes.
    Uses timezone-aware UTC time and Pillow's textbbox for text measurement.
    """
    # Pick base image
    if IMAGES == ["__placeholder__"]:
        base = Image.open(BytesIO(PLACEHOLDER_BYTES)).convert("RGB")
        total = 1
        idx_display = 1
    else:
        idx = clamp_index(idx)
        base = Image.open(IMAGES[idx]).convert("RGB")
        total = len(IMAGES)
        idx_display = idx + 1

    # Compose overlay text
    draw = ImageDraw.Draw(base)
    font = ImageFont.load_default()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    overlay = f"{now_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}"

    # Measure text using textbbox (Pillow ≥ 8.0)
    bbox = draw.textbbox((0, 0), overlay, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]

    # Draw background box + text
    pad = 6
    x, y = 10, 10
    draw.rectangle([x - pad, y - pad, x + tw + pad, y + th + pad], fill=(0, 0, 0))
    draw.text((x, y), overlay, fill=(255, 255, 255), font=font)

    # Encode JPEG
    out = BytesIO()
    base.save(out, format="JPEG", quality=85)
    return out.getvalue()


# ------------------------------
# SOAP helpers (SOAP 1.2)
# ------------------------------
SOAP_ENV = "http://www.w3.org/2003/05/soap-envelope"
NS = {
    "s": SOAP_ENV,
    "tds": "http://www.onvif.org/ver10/device/wsdl",
    "trt": "http://www.onvif.org/ver10/media/wsdl",
    "tptz": "http://www.onvif.org/ver20/ptz/wsdl",
    "tt": "http://www.onvif.org/ver10/schema",
}

def soap_env(body_elem: ET.Element) -> ET.Element:
    env = ET.Element(ET.QName(SOAP_ENV, "Envelope"))
    body = ET.SubElement(env, ET.QName(SOAP_ENV, "Body"))
    body.append(body_elem)
    return env

def soap_fault(reason: str, code_text="Sender", subcode_text="NotSupported") -> ET.Element:
    fault = ET.Element(ET.QName(SOAP_ENV, "Fault"))
    code = ET.SubElement(fault, "Code")
    ET.SubElement(code, "Value").text = f"s:{code_text}"
    sub = ET.SubElement(code, "Subcode")
    ET.SubElement(sub, "Value").text = subcode_text
    rsn = ET.SubElement(fault, "Reason")
    ET.SubElement(rsn, "Text").text = reason
    return soap_env(fault)

def soap_response(root: ET.Element) -> Response:
    data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return Response(data, mimetype="application/soap+xml; charset=utf-8")

def parse_action() -> tuple[str | None, str | None, ET.Element | None]:
    try:
        tree = ET.fromstring(request.data or b"")
    except ET.ParseError:
        return (None, None, None)
    body = tree.find(f"{{{SOAP_ENV}}}Body")
    if body is None or not list(body):
        return (None, None, None)
    op = list(body)[0]
    tag = op.tag
    if "}" in tag:
        ns, local = tag[1:].split("}")
    else:
        ns, local = (None, tag)
    return (ns, local, op)


# -------- Device Service (SOAP 1.2) --------
@app.post("/onvif/device_service")
def onvif_device():
    """
    All Device operations require HTTP Basic auth EXCEPT the deliberate vuln:
    - GetSystemBackup -> allowed without auth, returns base64 backup with leaked creds
    """
    base = host_base().rstrip("/")
    ns, action, op = parse_action()

    # Deliberate unauth vulnerability
    if action == "GetSystemBackup":
        # Build a tiny XML "backup" and return base64 in tt:BackupFile
        backup_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<backup>
  <device model="BlueFlex-Cam PTZ100" firmware="2.0.0"/>
  <users>
    <user role="admin" username="{ADMIN_USER}" password="{ADMIN_PASS}"/>
  </users>
</backup>""".encode("utf-8")
        b64 = base64.b64encode(backup_xml).decode("ascii")
        rsp = ET.Element(ET.QName(NS["tds"], "GetSystemBackupResponse"))
        files = ET.SubElement(rsp, ET.QName(NS["tds"], "BackupFiles"))
        f = ET.SubElement(files, ET.QName(NS["tt"], "BackupFile"))
        name = ET.SubElement(f, ET.QName(NS["tt"], "Name"))
        name.text = "system_backup.xml"
        data = ET.SubElement(f, ET.QName(NS["tt"], "Data"))
        data.text = b64
        return soap_response(soap_env(rsp))
    
    if action == "GetUsers":
        rsp = ET.Element(ET.QName(NS["tds"], "GetUsersResponse"))

        # admin
        u = ET.SubElement(rsp, ET.QName(NS["tds"], "User"))
        ET.SubElement(u, ET.QName(NS["tt"], "Username")).text = ADMIN_USER
        ET.SubElement(u, ET.QName(NS["tt"], "Password")).text = ADMIN_PASS
        ET.SubElement(u, ET.QName(NS["tt"], "UserLevel")).text = "Administrator"

        return soap_response(soap_env(rsp))

    if action == "GetDeviceInformation":
        rsp = ET.Element(ET.QName(NS["tds"], "GetDeviceInformationResponse"))
        ET.SubElement(rsp, "Manufacturer").text = "BlueFlex"
        ET.SubElement(rsp, "Model").text = "PTZ100"
        ET.SubElement(rsp, "FirmwareVersion").text = "2.0.0"
        ET.SubElement(rsp, "SerialNumber").text = "BF-PTZ-0001"
        ET.SubElement(rsp, "HardwareId").text = "BF-PTZ"
        return soap_response(soap_env(rsp))

    if action == "GetServices":
        rsp = ET.Element(ET.QName(NS["tds"], "GetServicesResponse"))
        for (nsuri, path) in [
            (NS["tds"], "/onvif/device_service"),
            (NS["trt"], "/onvif/media"),
            (NS["tptz"], "/onvif/ptz"),
        ]:
            svc = ET.SubElement(rsp, "Service")
            ET.SubElement(svc, "Namespace").text = nsuri
            ET.SubElement(svc, "XAddr").text = f"{base}{path}"
            ver = ET.SubElement(svc, "Version")
            ET.SubElement(ver, "Major").text = "2"
            ET.SubElement(ver, "Minor").text = "0"
        return soap_response(soap_env(rsp))

    if action == "GetCapabilities":
        rsp = ET.Element(ET.QName(NS["tds"], "GetCapabilitiesResponse"))
        caps = ET.SubElement(rsp, "Capabilities", attrib={"xmlns:tt": NS["tt"]})
        dev = ET.SubElement(caps, "Device")
        media = ET.SubElement(caps, "Media")
        ptz = ET.SubElement(caps, "PTZ")
        ET.SubElement(dev, "XAddr").text = f"{base}/onvif/device_service"
        ET.SubElement(media, "XAddr").text = f"{base}/onvif/media"
        ET.SubElement(ptz, "XAddr").text = f"{base}/onvif/ptz"
        return soap_response(soap_env(rsp))

    return soap_response(soap_fault(f"Unsupported Device action: {action}"))

# -------- Media Service (SOAP 1.2) --------
@app.post("/onvif/media")
@require_basic_auth("ONVIF Media")
def onvif_media():
    base = host_base().rstrip("/")
    ns, action, op = parse_action()

    if action == "GetProfiles":
        rsp = ET.Element(ET.QName(NS["trt"], "GetProfilesResponse"))
        prof = ET.SubElement(rsp, ET.QName(NS["trt"], "Profiles"), attrib={"token": "Profile_1", "fixed": "true"})
        ET.SubElement(prof, ET.QName(NS["tt"], "Name")).text = "MainProfile"
        return soap_response(soap_env(rsp))

    if action == "GetStreamUri":
        rsp = ET.Element(ET.QName(NS["trt"], "GetStreamUriResponse"))
        m = ET.SubElement(rsp, ET.QName(NS["trt"], "MediaUri"))
        ET.SubElement(m, ET.QName(NS["tt"], "Uri")).text = f"http://{request.host}/mjpeg"
        ET.SubElement(m, ET.QName(NS["tt"], "InvalidAfterConnect")).text = "false"
        ET.SubElement(m, ET.QName(NS["tt"], "InvalidAfterReboot")).text = "false"
        ET.SubElement(m, ET.QName(NS["tt"], "Timeout")).text = "PT10S"
        return soap_response(soap_env(rsp))

    if action == "GetSnapshotUri":
        rsp = ET.Element(ET.QName(NS["trt"], "GetSnapshotUriResponse"))
        m = ET.SubElement(rsp, ET.QName(NS["trt"], "MediaUri"))
        ET.SubElement(m, ET.QName(NS["tt"], "Uri")).text = f"{base}/snapshot"
        ET.SubElement(m, ET.QName(NS["tt"], "InvalidAfterConnect")).text = "false"
        ET.SubElement(m, ET.QName(NS["tt"], "InvalidAfterReboot")).text = "false"
        ET.SubElement(m, ET.QName(NS["tt"], "Timeout")).text = "PT10S"
        return soap_response(soap_env(rsp))

    return soap_response(soap_fault(f"Unsupported Media action: {action}"))

# -------- PTZ Service (SOAP 1.2) --------
@app.post("/onvif/ptz")
@require_basic_auth("ONVIF PTZ")
def onvif_ptz():
    global PTZ_INDEX
    ns, action, op = parse_action()

    if action == "ContinuousMove":
        # Look for Velocity/PanTilt[@x]
        x = 0.0
        vel = op.find(".//{http://www.onvif.org/ver20/ptz/wsdl}Velocity")
        if vel is None:
            vel = op.find(".//Velocity")
        if vel is not None:
            pt = vel.find(".//{http://www.onvif.org/ver10/schema}PanTilt")
            if pt is None:
                pt = vel.find(".//PanTilt")
            if pt is not None:
                try:
                    x = float(pt.attrib.get("x", "0"))
                except ValueError:
                    x = 0.0
        step = 1 if x < -1e-6 else (-1 if x > 1e-6 else 0)
        with PTZ_LOCK:
            PTZ_INDEX = clamp_index(PTZ_INDEX + step)
        rsp = ET.Element(ET.QName(NS["tptz"], "ContinuousMoveResponse"))
        return soap_response(soap_env(rsp))

    if action == "Stop":
        rsp = ET.Element(ET.QName(NS["tptz"], "StopResponse"))
        return soap_response(soap_env(rsp))

    return soap_response(soap_fault(f"Unsupported PTZ action: {action}"))

# -------- Snapshot (JPEG) --------
@app.get("/snapshot")
@require_basic_auth("Snapshot")
def snapshot():
    with PTZ_LOCK:
        idx = PTZ_INDEX
    return Response(snapshot_bytes(idx), mimetype="image/jpeg")

# Optional: tiny status helper (auth'd)
@app.get("/ptz/status")
@require_basic_auth("PTZ Status")
def ptz_status():
    with PTZ_LOCK:
        idx = PTZ_INDEX
    return jsonify({"ptz_index": idx, "frames": len(IMAGES)})

@app.get("/mjpeg")
@require_basic_auth("MJPEG")
def mjpeg():
    def gen():
        import time
        boundary = b"--frame\r\n"
        while True:
            with PTZ_LOCK:
                idx = PTZ_INDEX
            frame = snapshot_bytes(idx)
            yield boundary + b"Content-Type: image/jpeg\r\nContent-Length: " + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n"
            time.sleep(1)  # ~5 fps
    return Response(gen(), mimetype="multipart/x-mixed-replace; boundary=frame")

@app.get("/")
def index():
    return Response("""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BlueFlex PTZ100 Camera</title>
<style>
 body{margin:0;background:#0b1220;color:#e5ecf5;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial}
 .wrap{max-width:760px;margin:10vh auto;padding:2rem}
 .card{background:#101a2b;border:1px solid #1d2a44;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.35);padding:2rem}
 .title{margin:0 0 .25rem;font-size:1.25rem}
 .subtle{opacity:.75;font-size:.95rem;margin:0 0 1rem}
 .pill{display:inline-block;background:#2f7cff;color:#fff;border-radius:999px;padding:.25rem .6rem;font-size:.8rem}
 hr{border:none;border-top:1px solid #1d2a44;margin:1rem 0}
</style></head><body><div class="wrap"><div class="card">
<h1 class="title">BlueFlex PTZ100 Camera</h1>
<p class="subtle">Firmware 2.0.0 • ONVIF capable</p><hr>
<p>The embedded web interface is <b>disabled</b> on this device.</p>
<p class="subtle">To enable the management interface, please consult the user manual provided by the manufacturer.</p>
<span class="pill">Web UI disabled</span>
</div></div></body></html>""", mimetype="text/html")

# ------------------------------
# Main
# ------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "80"))
    app.run(host="0.0.0.0", port=port, debug=False)
