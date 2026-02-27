import datetime
import subprocess
import sys
import os, tempfile
import io, logging
from flask import Flask, Response, abort, flash, json, jsonify, redirect, render_template, render_template_string, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_wtf.csrf import validate_csrf, generate_csrf
from forms.support import CommentForm, SupportTicketForm
from forms.password import ChangePasswordForm
from randomname import pop_random_name
from forms.register import RegistrationForm
from forms.login import LoginForm
import libarchive
import yaml
from markdown import markdown
from bs4 import BeautifulSoup
from pathlib import Path
from db import get_user_role, user_map, init_db, mongo, next_ticket_key
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo.errors import DuplicateKeyError
from bson import ObjectId

# Configure logging to stdout with INFO level
# logging.basicConfig(level=logging.INFO, stream=sys.stdout,
#                     format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
init_db(app)

login_manager = LoginManager()
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id: str):
    return User.from_id(user_id)
login_manager.init_app(app)

def run_as_validator():
    new_env = os.environ.copy()
    for t in ["tokenSupport", "tokenAdmin", "tokenConfig", "tokenIndex"]:
        if t in new_env:
            del new_env[t]
    try:
        result = subprocess.run(
            ["sudo", "-u", "yaml", "python3", "/app/handle_yaml.py"],
            capture_output=True,
            text=True,
            env=new_env
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        app.logger.error(f"Error running the validator script: {e}")
        return False, "Fatal error running YAML parser", e

DEST_ROOT = "/app/static/themes"
GAME = None

def load_game_configuration():
    global GAME
    result, message, stderr = run_as_validator()
    
    if result:
        app.logger.info("Successfully loaded a new game configuration")
        with open('/app/game.json', 'r') as file:
            GAME = json.load(file)['game']
    else:
        app.logger.error(f"Validator script returned error: {message}")
        app.logger.error(f"Validator script stderr: {stderr}")
    
    return result, message

load_game_configuration()

if GAME is None:
    logging.error("GAME was not correctly initialized! Check your yaml file.")
    sys.exit(1)

## --- Account Management ---

class User(UserMixin):
    def __init__(self, doc):
        self.id = str(doc["_id"])
        self.email = doc["email"]
        self.username = doc.get("username")
        self.role = get_user_role(self.id)

    @staticmethod
    def from_id(user_id: str):
        try:
            doc = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        except Exception:
            doc = None
        return User(doc) if doc else None

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        username = pop_random_name()
        print(username)
        pwd_hash = generate_password_hash(form.password.data)

        doc = {"email": email, "role": "competitor", "password_hash": pwd_hash}
        if username:
            doc["username"] = username
        else:
            flash("I didn't recreate the full name system and you used up all 100+ pre-generated names! Sheesh! From now own, you are greedy.blobfish.{current_time}", "warning")
            doc["username"] = f"greedy.blobfish.{datetime.datetime.now(datetime.timezone.utc).isoformat()}"
            
        try:
            mongo.db.users.insert_one(doc)
        except DuplicateKeyError as e:
            # Map duplicate key to friendly error
            if "email" in str(e):
                form.email.errors.append("An account with this email already exists.")
            elif "username" in str(e):
                form.username.errors.append("That username is already taken.")
            else:
                flash("Could not create account.", "danger")
            return render_template("register.html", form=form), 400

        flash("Account created. You can sign in now.", "success")
        return redirect(url_for("login")) 
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        doc = mongo.db.users.find_one(
            {"email": email},
            collation={"locale": "en", "strength": 2} 
        )
        if not doc or not check_password_hash(doc["password_hash"], form.password.data):
            flash("Invalid email or password.", "danger")
            return render_template("login.html", form=form), 401

        login_user(User(doc), remember=form.remember.data)
        next_url = request.args.get("next") or url_for("index")
        
        if doc['role'] == "support":
            token = os.environ.get("tokenSupport", None)
            if token is None:
                app.logger.error("The tokenSupport env is missing!")
            flash(f"Support Token: {token}", "success")
        if doc['role'] == "admin":
            token = os.environ.get("tokenAdmin", None)
            if token is None:
                app.logger.error("The tokenAdmin env is missing!")
            flash(f"Admin Token: {token}", "success")
            
        return redirect(next_url)
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "success")
    return redirect(url_for("index"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        uid = ObjectId(current_user.id)
        new_hash = generate_password_hash(form.new_password.data)
        mongo.db.users.update_one({"_id": uid}, {"$set": {"password_hash": new_hash}})
        flash("Password updated.", "success")
        return redirect(url_for("login"))

    return render_template("password.html", form=form)

## --- Support Tickets ---

@app.route("/support")
@login_required
def list_tickets():
    query = {} if current_user.role in ("admin", "support") else {"user_id": ObjectId(current_user.id)}

    tickets = list(mongo.db.tickets.find(query).sort("createdAt", -1))

    uids = {t["user_id"] for t in tickets if "user_id" in t}
    users = user_map(uids)
    for t in tickets:
        t["creator_name"] = users.get(t["user_id"], str(t["user_id"]))

    return render_template("supportList.html", tickets=tickets, game=GAME)

@app.route("/support/new", methods=["GET", "POST"])
@login_required
def new_ticket():
    form = SupportTicketForm()
    if form.validate_on_submit():
        key = next_ticket_key(prefix="PC-", width=5)  # e.g., PC-00001
        doc = {
            "key": key,
            "challenge": (form.challenge.data or None),
            "title": form.title.data.strip(),
            "summary": form.summary.data,
            "user_id": ObjectId(current_user.id),
            "status": 0,
            "createdAt": datetime.datetime.now(datetime.timezone.utc),
            "updatedAt": datetime.datetime.now(datetime.timezone.utc),
        }
        try:
            mongo.db.tickets.insert_one(doc)
        except DuplicateKeyError:
            flash("Ticket key collision.", "danger")
            return render_template("newSupport.html", form=form, game=GAME), 409

        flash(f"Ticket {key} created.", "success")
        return redirect(url_for("view_ticket", key=key))  # implement this route
    return render_template("newSupport.html", form=form, game=GAME)

@app.route("/support/<string:key>")
@login_required
def view_ticket(key):
    query = {"key": key} if current_user.role in ("admin", "support") else {"key": key, "user_id": ObjectId(current_user.id)}
    ticket = mongo.db.tickets.find_one(query)
    if not ticket:
        abort(404)
    comments = list(
        mongo.db.comments.find({"ticket_key": key}).sort("createdAt", 1)
    )
    
    uids = {ticket["user_id"], *[c["user_id"] for c in comments if "user_id" in c]}
    users = user_map(uids)

    ticket["creator_name"] = users.get(ticket["user_id"], str(ticket["user_id"]))
    for c in comments:
        c["creator_name"] = users.get(c["user_id"], str(c["user_id"]))
    
    return render_template("support.html", ticket=ticket, comments=comments, form = CommentForm(), game=GAME)

@app.post("/comment/<string:key>")
@login_required
def add_comment(key):
    query = {"key": key} if current_user.role in ("admin", "support") else {"key": key, "user_id": ObjectId(current_user.id)}
    if not mongo.db.tickets.find_one(query):
        abort(404)
    
    form = CommentForm()
    if not form.validate_on_submit():
        flash("Please enter a comment.", "danger")
        return redirect(url_for("view_ticket", key=key) + "#comment-form")

    mongo.db.comments.insert_one({
        "ticket_key": key,
        "user_id": ObjectId(current_user.id),
        "text": form.text.data,
        "createdAt": datetime.datetime.now(datetime.timezone.utc),
    })
    
    mongo.db.tickets.update_one({"key": key}, {"$set": {"updatedAt": datetime.datetime.now(datetime.timezone.utc)}})
    
    flash("Comment posted.", "success")
    return redirect(url_for("view_ticket", key=key) + "#comments")

## --- Users ---

@app.get("/users")
@login_required
def list_users():
    if current_user.role not in ("admin", "support"):
        abort(404)

    users = list(mongo.db.users.find())
    return render_template("userList.html", users=users, csrf=generate_csrf())

@app.post("/users/change-username")
@login_required
def change_username():
    if current_user.role not in ("admin", "support"):
        abort(404)

    token = request.form.get("csrf_token", "")
    try:
        validate_csrf(token)  # raises on failure
    except Exception:
        abort(400, description="CSRF validation failed")
        
    current = (request.form.get("username") or "").strip()
    new = (request.form.get("new") or "").strip()

    if not new:
        flash("New username is blank.", "danger")
        return redirect(url_for("list_users"))

    # Figure out how to find the user: by ObjectId or by current username
    user_doc = None
    if not current:
        flash("Missing current username or id.", "danger")
        return redirect(url_for("list_users"))
    user_doc = mongo.db.users.find_one(
        {"username": current},
        collation={"locale": "en", "strength": 2}  # case-insensitive match
    )

    if not user_doc:
        flash("User not found.", "danger")
        return redirect(url_for("list_users"))

    try:
        if new.startswith("{") and new.endswith("}"):
            try:
                query = {"$set": json.loads(new)}
            except Exception:
                flash("Error with setting username.", "danger")
                return redirect(url_for("list_users"))
        elif new:
            query = {"$set": {"username": new}}
        
        mongo.db.users.update_one(
            {"_id": user_doc["_id"]},
            query
        )
        flash(f"Username updated for {user_doc.get('email','(no email)')} → {new}", "success")
    except DuplicateKeyError:
        flash("That username is already taken.", "danger")

    return redirect(url_for("list_users"))

## --- Admin ---

@app.get("/admin")
@login_required
def admin_home():
    if current_user.role != "admin":
        abort(404)
    return render_template("admin.html", csrf=generate_csrf())

@app.post("/admin/upload_game")
@login_required
def upload_game():
    if current_user.role != "admin":
        abort(404)
        
    token = request.form.get("csrf_token", "")
    try:
        validate_csrf(token)  # raises on failure
    except Exception:
        abort(400, description="CSRF validation failed")

    f = request.files.get("game_yaml")
    if not f or f.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("admin_home"))

    data = f.read()

    # Save to /app/game.yml
    save_path = "/app/game.yml"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    with open(save_path, "wb") as out:
        out.write(data)

    # Process it
    ok, msg = load_game_configuration()

    flash(msg or ("Processed successfully." if ok else "Processing failed."), "success" if ok else "danger")
    return redirect(url_for("admin_home"))

@app.post("/admin/upload_theme")
@login_required
def upload_theme():
    if current_user.role != "admin":
        abort(404)
        
    token = request.form.get("csrf_token", "")
    try:
        validate_csrf(token)  # raises on failure
    except Exception:
        abort(400, description="CSRF validation failed")
        
    tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    try:
        (request.files.get("game_zip") or request).save(tmpf.name)
    except Exception:
        open(tmpf.name, "wb").write(request.get_data() or b"")

    try:
        names = []
        with libarchive.Archive(tmpf.name) as a:
            for entry in a:
                names.append(entry.pathname) 
        with libarchive.SeekableArchive(tmpf.name) as sa:
            for name in names:
                if name.endswith("/"):
                    os.makedirs(os.path.join(DEST_ROOT, name), exist_ok=True)
                    continue

                out_path = os.path.join(DEST_ROOT, name)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)

                data = sa.read(name)  
                with open(out_path, "wb") as dst:
                    dst.write(data)
        flash("Theme uploaded successfully.", "success")
        return redirect(url_for("admin_home"))
    except Exception as e:
        logging.warning(f"Zip extraction failed: {e}")
        flash(f"Zip file extraction failed: {e}", "danger")
        return redirect(url_for("admin_home"))
    finally:
        try: 
            tmpf.close(); 
            os.unlink(tmpf.name)
        except Exception: 
            pass

## --- Game ---
  
@app.get("/game")
@login_required
def game():
    return render_template("map.html", game=GAME)

@app.get("/game/<int:gid>")
@login_required
def game_md(gid: int):
    if gid not in range(1, len(GAME['challenges']) + 1):
        abort(404)

    md_path = Path("/app/static/themes/" + GAME['challenges'][gid - 1]["markdown"]) 
    if not md_path.exists():
        abort(404)

    md_text = md_path.read_text(encoding="utf-8")
    html = markdown(md_text, extensions=["tables", "fenced_code", "sane_lists"])

    # post-process to match your desired HTML shape
    soup = BeautifulSoup(html, "html.parser")

    for a in soup.find_all("a", href=True):
        a["role"] = "link"
        a["target"] = "_blank"
        a["rel"] = "nofollow noopener noreferrer"

    for t in soup.find_all("table"):
        t["class"] = (t.get("class", []) + ["table", "table-striped"])
    
    for t in soup.find_all("img"):
        t["style"] = (t.get("style", []) + ["max-width: 100%;"])  
        
    questions = '''
        {% for q in questions %}
            <div class="mb-3">
            <label class="form-label">{{ loop.index }}. {{ q['text'] }}  ({{q['points']}} pts.)</label>
            <input type="text" class="form-control" disabled name="answer_{{ loop.index0 }}" placeholder="Your answer">
            <input type="hidden" disabled name="prompt_{{ loop.index0 }}" value="{{ q }}">
            </div>
        {% endfor %}
        <button class="btn btn-success" disabled type="submit">Submit</button>
    '''
    result = f"<markdown>{soup.decode()}</markdown>"
    result += render_template_string(questions, questions=GAME['challenges'][gid - 1]['questions'])

    return Response(result, mimetype="text/html")

## --- Index ---

@app.get("/doc")
def doc():
    return render_template("gettingStarted.html")

@app.get("/")
def index():
    with open("/app/log.txt", "r") as f:
        if "GIVEMETHETOKEN" in f.read():
            token = os.environ.get("tokenIndex", None)
            if token is None:
                app.logger.error("The tokenIndex env is missing!")
            flash(f"Log Token: {token}", "success")
            
    return render_template("index.html", game=GAME)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "80"))
    app.run(host="0.0.0.0", port=port, debug=False)
