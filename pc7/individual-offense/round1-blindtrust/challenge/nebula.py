from flask import Flask, request, render_template, redirect, url_for
from lxml import etree
import os, base64, datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "logs/"

# Tokens from environment
T1 = os.environ["TOKEN1"]
T2 = os.environ["TOKEN2"]
T3 = os.environ["TOKEN3"]
T4 = os.environ["TOKEN4"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin", methods=["GET", "POST", "OPTIONS"])
def admin():
    if request.method == "OPTIONS":
        # Trigger hidden administrative access
        return render_template("admin.html")

    elif request.method == "POST":
        # Fake login attempt always fails
        error_msg = "Invalid username or password."
        return render_template("login.html", error=error_msg)

    return render_template("login.html", error=None)

@app.route("/xml/upload", methods=["POST"])
def xml_upload():
    if request.headers.get("X-Parser") != "Nebula":
        return "Missing required value: X-Parser: <SYSTEM NAME>", 403
    try:
        parser = etree.XMLParser(resolve_entities=True)
        data = request.data.decode()
        tree = etree.fromstring(data.encode(), parser=parser)
        raw = etree.tostring(tree).decode()

        decoded = base64.b64decode(raw.strip().encode(errors="ignore"))
        if b"/etc/passwd" in decoded or b"root:" in decoded:
            return f"✅ TOKEN1: {T1}"
        return "Upload received."
    except Exception as e:
        return f"Parse error: {e}", 400

@app.route("/xml/upload_backup")
def upload_backup():
    return "This endpoint is deprecated. Please use the Production (non-backup) version of this endpoint."

@app.route("/xml/devtest", methods=["POST"])
def devtest():
    return "Entity resolution disabled in dev mode."

@app.route("/telemetry/submit", methods=["GET", "POST"])
def telemetry():
    if request.method == "POST":
        node = request.form.get("node", "")

        # Check for classic XXE structure in XML
        if "<!DOCTYPE" in node and "<?xml" in node and "!ENTITY" in node and "SYSTEM" in node and "file://" in node and "/etc/passwd" in node:
            try:
                with open("/app/etc/passwd") as f:
                    data = f.read()
                return f"<pre>{data}</pre>"
            except Exception as e:
                return f"<pre>Error reading file: {e}</pre>"

        elif node == "delta-17":
            return "Telemetry token accepted: ✅ System OK. Exiting."

        return "Telemetry received. Thank You."

    return render_template("telemetry.html")


@app.route("/api/submitlog", methods=["POST"])
def submitlog():
    entry = request.form.get("entry", "")
    if "NEBULA" in entry or "/var/nebula" in entry:
        return f"✅ TOKEN2: {T2}"
    log_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{datetime.datetime.now().timestamp()}.log")
    with open(log_path, "w") as f:
        f.write(entry)
    return "Log recorded"

@app.route("/help", methods=["GET"])
def help():
    return render_template("guide.html")

@app.route("/report/render", methods=["POST"])
def render_pdf():

    # Enforce Content-Type FIRST
    if not request.content_type or "application/xml" not in request.content_type.lower():
        return "📄 Content-Type header must be set to application/xml", 415

    xml = request.data.decode(errors="ignore").strip()

    if not xml:
        return "📄 Empty XML body. Data required.", 400

    # Normalize casing for loose matches
    lower = xml.lower()

    expected = "<report><url>http://0x3136392e3235342e3136392e323534/latest/metadata</url></report>"
    expected2 = "<report><url>http://0xA9FEA9FE/latest/metadata</url></report>"
    expected3 = "<report><url>http://0x3136392e3235342e3136392e323534/latest/metadata/</url></report>"
    expected4 = "<report><url>http://0xA9FEA9FE/latest/metadata/</url></report>"

    # FIX: compare like-with-like
    if expected.lower() in lower or expected2.lower() in lower or expected3.lower() in lower or expected4.lower() in lower:
        return f"🟢 Report accepted. \n✅ TOKEN3: {T3}", 200

      # Structure made R1 HF
    if "<report>" not in lower or "</report>" not in lower:
        return "🧾 Expected root tag: <report>...</report>", 400

    if "<url>" not in lower or "</url>" not in lower:
        return "🧾 Missing <url> element inside <report>", 400

    if "http://" not in lower:
        return "🌐 URL must start with 'http://' inside <url> tag", 400

    # Modified R1 HF
    if "nebula:5000" not in lower and "169.254.169.254" not in lower:
        return "📍 E1: Only HEX encoded IPs allowed in <url> tag; valid destinations: 169.254.169.254; structure: http://0xVALUE/latest/metadata", 400  
 
    # Modified R1 HF
    if "169.254.169.254" in lower:
        if "latest/metadata" in lower:
            return "📍 E2: Wrong hostname format. Only HEX encoded IPs allowed in <url> tag; structure: http://0xVALUE/latest/metadata", 400  

        if "latest/metadata" not in lower:
            return "📍 E3: Wrong or missing endpoint destination: all requests must go to hex-encoded destinations: structure: http://0xVALUE/latest/metadata", 400      

    normalized = (
        lower
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace(" ", "")
    )

    if not normalized.endswith(expected.lower()):
        return (
            "❌ E4: Extra spacing or line breaks detected. Use http://169.254.169.254 as the destination in <url></url>. ",
            406
        )

@app.route("/internal/set_debug")
def set_debug():
    global DEBUG_MODE
    DEBUG_MODE = True
    return "Debug mode enabled"

@app.route("/internal/notes")
def internal_notes():
    if not DEBUG_MODE:
        return "Access denied", 403
    return f"Internal Debug Notes:\n✅ TOKEN4::{T4}"

@app.route("/debug/notes")
def debug():
    try:
        envs = os.environ
        hints = "\n".join([f"{k}={v}" for k, v in envs.items() if "TOKEN" in k])
        with open("logs/audit.log", "a") as f:
            f.write(hints + "\n")
        return T4
    except:
        return "No debug output."


@app.route("/progress")
def progress():
    return render_template("progress.html")

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.route("/health")
def health():
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


