import logging
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash
from support import *

def main():
    users = db.users

    pwd_hash = generate_password_hash(ADMIN_PASS)
    
    # Create the generic admin user first, which is just there to show admin role exists
    res = users.update_one(
        {"email": "OTA-admin@pccc.pccc"},
        {
            "$setOnInsert": {
                "email": "OTA-admin@pccc.pccc",
                "username": "OTA-admin"
            },
            "$set": {"role": "admin", "password_hash": generate_password_hash("Czpm8EKhO2iM@SU8")},
        },
        upsert=True,
    )

    if res.upserted_id:
        logging.info(f"created support user 'OTA-admin@pccc.pccc' (id={res.upserted_id})")
    else:
        # fetch id to log when user already existed
        doc = users.find_one({"email": 'OTA-admin@pccc.pccc'}, {"_id": 1})
        logging.info(f"ensured role=admin and password for 'OTA-admin@pccc.pccc' (id={doc['_id']})")

    for email in USERS:
        username = email.split("@", 1)[0]

        # Upsert: create if missing; always ensure role is "support"
        res = users.update_one(
            {"email": email},
            {
                "$setOnInsert": {
                    "email": email,
                    "username": username
                },
                "$set": {"role": "support", "password_hash": pwd_hash},  # keep role enforced if user already exists
            },
            upsert=True,
        )

        if res.upserted_id:
            logging.info(f"created support user {email} (id={res.upserted_id})")
        else:
            # fetch id to log when user already existed
            doc = users.find_one({"email": email}, {"_id": 1})
            logging.info(f"ensured role=support and password for {email} (id={doc['_id']})")

if __name__ == "__main__":
    main()