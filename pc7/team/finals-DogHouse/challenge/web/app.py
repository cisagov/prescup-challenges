from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import sys

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, "uploads")
REQUIRED_MIME = "application/pdf"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "ctf-dev-secret"

TEAM = [
    ("Bob Taylor", "CEO"),
    ("Alice Jennings", "Storage Architect"),
    ("Joe Williams", "Ops Engineer"),
    ("Eve Smith", "Support Tech"),
    ("Ryan Jones", "Manager"),
]

ABOUT = (
    "Cloud Tech Foundry provides third-party cloud hosting and secure data storage "
    "across multiple global datacenters. Pay-as-you-go packages, SLA-backed uptime, "
    "and managed support to keep your data accessible and safe."
)


@app.route("/")
def home():
    return render_template("home.html", about=ABOUT, company="CTF")


@app.route("/team")
def team():
    return render_template("team.html", team=TEAM)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)

        f = request.files["file"]
        if f.filename == "":
            flash("No selected file")
            return redirect(request.url)

        client_mime = (f.mimetype or "").lower()
        filename = secure_filename(f.filename)
        mime_ok = client_mime == REQUIRED_MIME

        if mime_ok:
            upload_dir = app.config['UPLOAD_FOLDER']
            for item in os.listdir(upload_dir):
                item_path = os.path.join(upload_dir, item)
                try:
                    if os.path.isfile(item_path) or os.path.islink(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        import shutil
                        shutil.rmtree(item_path)
                except Exception as e:
                    print(f"Failed to delete {item_path}: {e}", file=sys.stderr)

            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            f.save(save_path)
            flash(f"Uploaded successfully as {filename}")
            os.system("/app/upload_script.sh")
            return redirect(url_for("upload"))
        else:
            flash(
                f"Please upload a pdf."
            )
            return redirect(request.url)

    return render_template("upload.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
