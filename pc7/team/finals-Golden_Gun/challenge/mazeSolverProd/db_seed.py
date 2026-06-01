#!/usr/bin/env python3
import os, sys
import mysql.connector
from mysql.connector import errorcode

# DB connection settings (override via ENV)
DB_HOST = os.getenv("DB_HOST", "database")
DB_NAME = os.getenv("DB_NAME", "pop")
DB_USER = os.getenv("DB_USER", "user")
DB_PASS = os.getenv("DB_PASS", "password")
TABLE   = os.getenv("DB_TABLE", "superSecretTableOfMazes")

TOKEN = os.getenv("secondToken")

def fail(code: int, msg: str):
    print(msg, file=sys.stderr)
    sys.exit(code)

def main():
    if not TOKEN:
        fail(3, "TOKEN is not set.")

    value = TOKEN

    try:
        cnx = mysql.connector.connect(
            host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS
        )
    except mysql.connector.Error as e:
        fail(1, f"DB connect failed: {e}")

    try:
        cur = cnx.cursor()
        cur.execute(f"INSERT IGNORE INTO `{TABLE}` (mazeIdea) VALUES (%s)", [value])
        cnx.commit()
        cur.close()
        cnx.close()
        print("Seed OK")
        sys.exit(0)
    except mysql.connector.Error as e:
        try:
            cnx.close()
        except Exception:
            pass
        fail(2, f"DB insert failed: {e}")

if __name__ == "__main__":
    main()
