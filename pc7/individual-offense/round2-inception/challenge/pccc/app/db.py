import os
from bson import ObjectId
from flask_pymongo import PyMongo

mongo = PyMongo()

def init_db(app):
    app.config["MONGO_URI"] = os.getenv("MONGO_URI")
    mongo.init_app(app)
    
def next_ticket_key(prefix="PC-", width=3):
    doc = mongo.db.counters.find_one_and_update(
        {"_id": "ticket"},
        {"$inc": {"seq": 1}},
        return_document=True,
        upsert=True,
    )
    n = doc["seq"]
    return f"{prefix}{n:0{width}d}"

def user_map(uids):
    """Return {_id: username_or_email} for a set of ObjectIds."""
    if not uids:
        return {}
    cur = mongo.db.users.find({"_id": {"$in": list(uids)}}, {"username": 1, "email": 1})
    return {d["_id"]: (d.get("username") or d.get("email") or str(d["_id"])) for d in cur}

def get_user_role(uid_str: str) -> str | None:
    doc = mongo.db.users.find_one({"_id": ObjectId(uid_str)}, {"role": 1, "roles": 1})
    if not doc:
        return None
    # support both a single "role" field or a "roles" array
    if "role" in doc and isinstance(doc["role"], str):
        return doc["role"]
    if "roles" in doc and isinstance(doc["roles"], list):
        for r in doc["roles"]:
            if r in ("admin", "support"):
                return r
    return None