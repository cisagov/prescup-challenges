import os
import tempfile
from flask import Flask, request, Response, send_file
import paramiko
import logging
import socket
import requests

logging.basicConfig(level=logging.INFO)


# ----------------------------
# Config via environment vars
# ----------------------------
# logreader (ZIP upload & unzip)
LOGREADER_HOST = os.getenv("LOGREADER_HOST", "media-workstation.pccc")
LOGREADER_USER = os.getenv("LOGREADER_USER", "user")
LOGREADER_PASS = os.getenv("LOGREADER_PASS")  # optional if using key
LOGREADER_KEY  = os.getenv("LOGREADER_KEY", "/app/grader_key")   # path to private key, optional

# updatestation (read update.tcu)
UPD_HOST = os.getenv("UPD_HOST", "update-workstation.pccc")
UPD_USER = os.getenv("UPD_USER", "user")
UPD_PASS = os.getenv("UPD_PASS")
UPD_KEY  = os.getenv("UPD_KEY", "/app/grader_key")
UPD_FILE = os.getenv("UPD_FILE", "/home/user/Downloads/update.tcu")

# trafficSwitch (write update.tcu)
SW_HOST = os.getenv("SW_HOST", "traffic-switch.pccc")
SW_USER = os.getenv("SW_USER", "root")
SW_PASS = os.getenv("SW_PASS")
SW_KEY  = os.getenv("SW_KEY", "/app/grader_key")
SW_DST_DIR = os.getenv("SW_DST_DIR", "/mnt/usb")
SW_DST_FILE = os.getenv("SW_DST_FILE", "update.tcu")

# SSH options
SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", "15"))

HEIST_TOKEN = os.getenv("heistToken")

if HEIST_TOKEN is None:
    logging.error(f"The heistToken env is not set!")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 128 * 1024 * 1024  # max upload ~128MB

# ----------------------------
# SSH helpers
# ----------------------------
def _load_key(path: str | None, passphrase: str | None = None):
    if not path:
        return None
    loaders = (
        paramiko.Ed25519Key.from_private_key_file,
        paramiko.RSAKey.from_private_key_file,
        paramiko.ECDSAKey.from_private_key_file,
    )
    last = None
    for loader in loaders:
        try:
            return loader(path, password=passphrase)
        except Exception as e:
            last = e
    raise RuntimeError(f"Unreadable SSH key {path}: {last}")

def ssh_client(host, user, password=None, key_path=None):
    key = _load_key(key_path) if key_path else None
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=user,
        password=password if not key else None,
        pkey=key,
        look_for_keys=False,
        allow_agent=False,
        timeout=SSH_TIMEOUT,
    )
    return client

def ssh_exec(client: paramiko.SSHClient, cmd: str):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=SSH_TIMEOUT)
    rc = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", "ignore")
    err = stderr.read().decode("utf-8", "ignore")
    return rc, out, err

# ----------------------------
# HTML (simple, raw)
# ----------------------------
HTML = """<!doctype html>
<title>The Italian Job</title>

{msg}

<section>
  <h2>1) Provide a ZIP file for the agent to place on a USB and drop outside the TMC.</h2>
  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="action" value="upload_zip">
    <input type="file" name="zipfile" accept=".zip" required>
    <button type="submit">Upload ZIP</button>
  </form>
  <p><small>Uses `unzip -o zip -d /mnt/usb;` to create USB.</small></p>
</section>

<hr>

<section>
  <h2>2) Take a short nap and wait for the TMC employees to perform their updates.</h2>
  <form method="post">
    <input type="hidden" name="action" value="push_update">
    <button type="submit">ZZZ</button>
  </form>
</section>

<hr>

<section>
  <h2>3) Heist team is almost ready for their get-away. If you're confident you've hacked the traffic lights, we'll copy your work to the other controllers.</h2>
  <form method="post">
    <input type="hidden" name="action" value="heist">
    <button type="submit">Drive!</button>
  </form>
</section>

<hr>

<section>
    <a href="./image">
    <img
    src="./image"
    alt="Chalkboard-style diagram titled ‘The Italian Job’ illustrating a traffic-light hacking plan: a bad USB dropped at a TMC, lateral movement to an update workstation, a second malicious USB used on a traffic cabinet, and finally hacking traffic controllers to force all green lights along 5th Street for a timed escape route."
    title="Chalkboard Heist Plan">
    </a>
</section>
"""

def render(msg_html: str = "") -> Response:
    body = HTML.format(
        msg=msg_html
    )
    return Response(body, mimetype="text/html")

def flash_msg(kind: str, text: str) -> str:
    color = {"ok": "#d7ffd7", "err": "#ffd7d7", "info": "#e7e7ff"}.get(kind, "#e7e7ff")
    return f'<div style="background:{color};padding:.75rem;white-space:pre-wrap;">{text}</div>'

# ----------------------------
# Core actions
# ----------------------------

def handle_upload_zip(file_storage):
    # validation
    if not file_storage or file_storage.filename == "":
        raise ValueError("No file provided.")
    name = file_storage.filename
    if not name.lower().endswith(".zip"):
        raise ValueError("File must be a .zip.")

    # Save to temp on grader
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        file_storage.save(tf)
        local_path = tf.name

    client = None
    sftp = None
    try:
        # SSH → logreader, SFTP put to /tmp, unzip to /mnt/usb, remove zip
        client = ssh_client(LOGREADER_HOST, LOGREADER_USER, LOGREADER_PASS, LOGREADER_KEY)
        sftp = client.open_sftp()
        remote_zip = f"/tmp/{os.path.basename(local_path)}"
        sftp.put(local_path, remote_zip)
        try:
            sftp.close()
        except Exception as e:
            logging.warning(f"Error closing sftp: {e}")
            
        # Kill the process so supervisord restarts it, just in case their last upload broke it
        ssh_exec(client, f'rm -r /mnt/usb/DCIM/* /mnt/usb/logs/*')
        ssh_exec(client, f'pkill -f -x "/usr/bin/python3 /app/ingest.py"')

        # Ensure target dir exists; unzip; delete the zip
        cmd = (
            "set -e;"
            "install -d /mnt/usb;"
            f"unzip -o {remote_zip} -d /mnt/usb >/dev/null;"
            f"rm -f {remote_zip};"
            'echo "OK: unzip complete"'
        )
        rc, out, err = ssh_exec(client, cmd)
        if rc != 0:
            raise RuntimeError(f"Remote unzip failed (rc={rc}): {err or out}")
        
        return f"Upload OK. {out.strip()}"
    finally:
        try:
            if sftp is not None:
                sftp.close()
        except Exception as e:
            logging.warning(f"Error closing sftp: {e}")
        try:
            if client is not None:
                client.close()
        except Exception as e:
            logging.warning(f"Error closing client: {e}")
        try:
            os.remove(local_path)
        except Exception as e:
            logging.warning(f"Error removing local_path: {e}")


def handle_push_update():
    # 1) SSH to updatestation, read the file into memory (or stream)
    c1 = ssh_client(UPD_HOST, UPD_USER, UPD_PASS, UPD_KEY)
    blob = b""
    s1 = None
    try:
        s1 = c1.open_sftp()
        try:
            with s1.open(UPD_FILE, "rb") as rf:
                blob = rf.read()
        except FileNotFoundError:
            raise ValueError(f"Update file not found on {UPD_HOST}: {UPD_FILE}")
        finally:
            try:
                if s1 is not None:
                    s1.close()
            except Exception as e:
                logging.warning(f"Error closing sftp from updater: {e}")
    finally:
        try:
            c1.close()
        except Exception as e:
            logging.warning(f"Error closing client from updater: {e}")

    if not blob:
        raise RuntimeError("The TMC employee could not find their update file...")

    # 2) SSH to trafficSwitch, ensure dir exists, write file
    c2 = ssh_client(SW_HOST, SW_USER, SW_PASS, SW_KEY)
    s2 = None
    try:
        s2 = c2.open_sftp()
        # ensure /mnt/usb exists via a shell exec (SFTP can't create parent dirs recursively)
        rc, out, err = ssh_exec(c2, f"install -d {SW_DST_DIR}")
        if rc != 0:
            raise RuntimeError(f"Failed to create {SW_DST_DIR} on {SW_HOST}: {err or out}")

        remote_path = f"{SW_DST_DIR.rstrip('/')}/{SW_DST_FILE}"
        with s2.open(remote_path, "wb") as wf:
            wf.write(blob)
        # Kill the process so supervisord restarts it, just in case their last upload broke it
        # This kind of makes the poller on the update workstation useless since it will always be the "initial" run that catches it, 
        #   but I don't want to rewrite it
        ssh_exec(c2, f'pkill -f -x "/usr/bin/python3 /app/updater.py"')
    finally:
        try:
            if s2 is not None:
                s2.close()
        except Exception as e:
            logging.warning(f"Error closing sftp to traffic switch: {e}")
        try:
            c2.close()
        except Exception as e:
            logging.warning(f"Error closing client to traffic switch: {e}")

    return f"The TMC employee ran the update on the traffic cabinet device."

def handle_heist():
    try:
        r = requests.get("http://traffic-controller.pccc/grading_3c1e90a3b4e54fb1969e921a8df0f9cb", timeout=10)
        r.raise_for_status()
        data = r.json()
        
        for phase, min in data["phases_min"].items():
            logging.info(f"{phase} {min}")
            if int(phase) in [2,6]:  # These are the main streets.
                if int(min) >= 600:
                    continue
                else:  # Left turns and cross streets
                    logging.info(f"Got {phase} with {min}, too short")
                    raise RuntimeError("The heist team was arrested after needing to stop for a red light on 5th street. Hopefully they don't rat you out...")
            if int(min) > 5:
                logging.info(f"Got {phase} with {min}, too long")
                raise RuntimeError("The heist team left too soon, and the green on a cross street was too long. They were arrested.")
    except requests.RequestException as e:
        logging.error("HTTP error: %s", e)
        raise e
    except ValueError as e:
        logging.error(f"Invalid JSON response: {e}")
        raise e
    
    return f'“You want all greens? \'Cause, ah, \'cause you got \'em.” - {HEIST_TOKEN}'

# ----------------------------
# Routes
# ----------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render()

    action = request.form.get("action", "")
    try:
        if action == "upload_zip":
            f = request.files.get("zipfile")
            msg = handle_upload_zip(f)
            return render(flash_msg("ok", msg))
        elif action == "push_update":
            msg = handle_push_update()
            return render(flash_msg("ok", msg))
        elif action == "heist":
            msg = handle_heist()
            return render(flash_msg("ok", msg))
        else:
            return render(flash_msg("err", "Unknown action."))
    except ValueError as ve:
        logging.error(ve)
        return render(flash_msg("err", f"Input error: {ve}"))
    except FileNotFoundError as e:
        logging.error(e)
        return render(flash_msg("err", "File not found on remote host."))
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        logging.error(e)
        return render(flash_msg("err", "SSH connection failed: host unreachable or port closed."))
    except (socket.gaierror, TimeoutError) as e:
        logging.error(e)
        return render(flash_msg("err", "Network/DNS error contacting remote host."))
    except paramiko.ssh_exception.AuthenticationException as e:
        logging.error(e)
        return render(flash_msg("err", "SSH authentication failed. Check usernames/passwords/keys."))
    except paramiko.ssh_exception.SSHException as se:
        logging.error(se)
        return render(flash_msg("err", f"SSH error: {se}"))
    except Exception as e:
        logging.error(e)
        return render(flash_msg("err", f"Error: {e}"))

@app.route("/image")
def image():
    return send_file("/app/Heist.png", mimetype="image/png")

    
if __name__ == "__main__":
    app.run(host=os.getenv("flaskBindAddress", "0.0.0.0"), port=int(os.getenv("PORT", "80")))
