import logging
import os
import subprocess
import time
from flask import Flask, abort, flash, redirect, render_template, render_template_string, request, url_for
from flask_login import LoginManager, current_user, login_required, logout_user
from sqlalchemy import text
from werkzeug.utils import secure_filename
from forms.new_item import NewItemForm, DocumentForm
from sqlalchemy.orm import selectinload
import qrcode
import io
from flask import send_file
from PIL import Image
from PIL.ExifTags import TAGS
from models import User, Item, Document
from db import Session, SessionPawn, engine_pawn, engine
from urllib.parse import urlparse

# FYI: don't rename this folder unless we update the pawn sync task too
UPLOAD_FOLDER = "static/uploads"

app = Flask(__name__)

# key gets swapped in by entrypoint — do not hardcode
app.config['SECRET_KEY'] = os.getenv('secretKey')

# cookie policy stays relaxed inside internal net, tighten later if needed
app.config.update(
    SESSION_COOKIE_DOMAIN='.secondorder.pccc',
    SESSION_COOKIE_SECURE=False, 
    SESSION_COOKIE_SAMESITE='Lax'
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'http://pawn.secondorder.pccc/login'

def sync_uploads():
    r = subprocess.run(
        [
            "timeout", "10s", "rsync", "-az", "--delete",
            "-e", "ssh -o StrictHostKeyChecking=no",
            "/app/static/uploads/",
            "pawnuser@pawnshop.pccc:/app/static/uploads/"
        ],
        check=False,
    )
    return r.returncode

# Run it once on launch to sync up the images between servers
for _ in range(10):
    result = sync_uploads()
    if result == 0:
        break
    logging.warning("sync_uploads failed (rc=%s), retrying...", result)
    time.sleep(5)

def is_safe_url(target):
    # DNS aliases might shift — double-check nginx if this stops working
    parsed = urlparse(target)
    
    if not parsed.netloc:
        return True
    return parsed.scheme in ('http', 'https') and parsed.netloc.endswith('.secondorder.pccc')

@login_manager.user_loader
def load_user(user_id):
    # confirm user comes from pawn DB, not warehouse
    with SessionPawn() as session:
        return session.get(User, int(user_id))
    
@app.route("/logout")
def logout():
    # browser sometimes double-hits this, ignore
    logout_user()
    next_page = request.args.get('next')
    if not next_page or not is_safe_url(next_page):
        next_page = "http://pawn.secondorder.pccc/logout?next=http://warehouse.secondorder.pccc/"
    return redirect(next_page)

@app.route("/dashboard")
@login_required
def dashboard():
    # pretty empty for now — branding said no widgets until post-launch
    return render_template("dashboard.html")

@app.route("/pickups")
@login_required
def pickups():
    # confirmed rows = things user has already claimed
    with engine.connect() as conn:
        confirmed_rows = conn.execute(
            text(f"SELECT item_id, name, email FROM confirmed_pickups WHERE user_id = {current_user.id}")
        ).fetchall()

    confirmed_ids = {row.item_id for row in confirmed_rows}
    confirmed_map = {row.item_id: {"name": row.name, "email": row.email} for row in confirmed_rows}

    with engine_pawn.connect() as conn:
        pickup_rows = conn.execute(
            text(f"SELECT item_id, name, email FROM pickups WHERE user_id = {current_user.id}")
        ).fetchall()

    pickup_map = {row.item_id: {"name": row.name, "email": row.email} for row in pickup_rows}
    item_ids = [row.item_id for row in pickup_rows]

    claimed = []
    unclaimed = []

    if item_ids:
        with Session() as session:
            items = session.query(Item).filter(Item.id.in_(item_ids)).all()

        for item in items:
            # fallback if confirmed pickup isn't present
            pickup = confirmed_map.get(item.id) or pickup_map.get(item.id)
            entry = {"item": item, "pickup": pickup}
            if item.id in confirmed_ids:
                claimed.append(entry)
            else:
                unclaimed.append(entry)

    return render_template("pickups.html", unclaimed=unclaimed, claimed=claimed)


@app.route("/items")
@login_required
def item_list():
    # pretty sure this is just a dump of the user's inventory
    with Session() as session:
        items = session.query(Item).filter_by(user_id=current_user.id).all()
    return render_template("items.html", items=items)

@app.route("/items/<int:id>")
@login_required
def item_detail(id):
    # no sharing between users — don't remove the check
    with Session() as session:
        item = session.query(Item).options(selectinload(Item.documents)).get(id)
        if not item:
            abort(404)
        if not current_user.is_authenticated or current_user.id != item.user_id:
            abort(403) 
        return render_template("item_detail.html", item=item)

@app.route("/items/<int:item_id>/pickup")
@login_required
def pickup_qr(item_id):
    # this powers the QR code view for kiosk scanning
    with engine_pawn.connect() as conn:
        pickup = conn.execute(
            text(f"""
                SELECT name, email FROM pickups
                WHERE item_id = {item_id} AND user_id = {current_user.id}
            """)
        ).fetchone()

    if not pickup:
        abort(404)

    with Session() as session:
        item = session.query(Item).filter_by(id=item_id).first()

    if not item:
        abort(404)

    return render_template("pickup_qr.html", item=item, pickup=pickup)

@app.route("/items/<int:item_id>/pickup_qr.png")
@login_required
def pickup_qr_code(item_id):
    # needed by the tablet QR scanner — don't move
    with engine_pawn.connect() as conn:
        pickup = conn.execute(
            text(f"""
                SELECT name, email FROM pickups
                WHERE item_id = {item_id} AND user_id = {current_user.id}
            """)
        ).fetchone()

    if not pickup:
        abort(404)
        
    qr_url = url_for("claim_item", item_id=item_id, _external=True)
    img = qrcode.make(qr_url)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
    
@app.route("/items/<int:item_id>/claim", methods=["GET"])
@login_required
def claim_item(item_id):
    # redirect here after QR scan and confirm press
    with engine_pawn.connect() as conn:
        result = conn.execute(
            text(f"SELECT name, email FROM pickups WHERE item_id = {item_id} AND user_id = {current_user.id}")
        ).fetchone()

        if not result:
            abort(404)

        name, email = result

    with engine.begin() as conn:
        already = conn.execute(
            text(f"""
                SELECT 1 FROM confirmed_pickups
                WHERE item_id = {item_id} AND user_id = {current_user.id}
            """)
        ).fetchone()

        if already:
            flash("You've already marked this item as claimed.", "warning")
            return redirect(url_for("pickups"))

        conn.execute(
            text(f"""
                INSERT INTO confirmed_pickups (item_id, user_id, name, email)
                VALUES ({item_id}, {current_user.id}, '{name}', '{email}')
            """)
        )

    flash("Item marked as claimed!", "success")
    return redirect(url_for("pickups"))


@app.route("/items/new", methods=["GET", "POST"])
@login_required
def create_item():
    form = NewItemForm()
    
    if request.args.get("add_document") is not None:
        # this handles AJAX doc-adds on the new item form
        index = int(request.args.get("add_document"))
        dummy_form = DocumentForm(prefix=f"documents-{index}")
        return render_template_string("""
        <div class="document-group mb-3 border p-3 rounded position-relative" data-index="{{ index }}">
            {{ doc_form.file.label(class="form-label") }}
            {{ doc_form.file(class="form-control") }}
            {{ doc_form.documentDescription.label(class="form-label mt-2") }}
            {{ doc_form.documentDescription(class="form-control") }}
            <button type="button" class="btn-close position-absolute top-0 end-0 mt-2 me-2" aria-label="Remove"
                        onclick="removeDocument(this)"></button>
        </div>
        """, doc_form=dummy_form)

    if form.validate_on_submit():
        # only reachable from real form post, not from AJAX
        with Session() as session:
            item = Item(
                name=form.name.data,
                description=form.description.data,
                user_id=current_user.id
            )
            session.add(item) 
            session.flush()

            for doc_form in form.documents:
                file = doc_form.file.data
                desc = doc_form.documentDescription.data
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    save_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(save_path)

                    metadata = ""

                    try:
                        with Image.open(save_path) as img:
                            img.verify()
                        with Image.open(save_path) as img:
                            exif = img._getexif()
                            if exif:
                                pairs = []
                                for k, v in exif.items():
                                    key = f"X-CoverImage-{TAGS.get(k, str(k)).strip()}"
                                    val = str(v).strip()
                                    pairs.extend([key, val])
                                metadata = ",".join(pairs)
                    except Exception as e:
                        # some uploads throw here — ignore and move on
                        print(e)

                    doc = Document(
                        item_id=item.id,
                        filename=file.filename,
                        description=desc,
                        item_metadata=metadata
                    )
                    session.add(doc)

            session.commit()

        sync_uploads()
        flash("Item and documents saved successfully.", "success")
        return redirect(url_for("item_list"))

    return render_template("newItem.html", form=form)

@app.route("/")
def index():
    # storefront placeholder
    return render_template("index.html")
