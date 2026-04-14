import sqlite3
import base64
import subprocess
import json

# Path to the SQLite database
SQLITE_DB_PATH = "./root/android_dump/data/data/com.specter.securechat/databases/messages.db"
CACHE_KEY_PATH = "./root/android_dump/data/data/com.specter.securechat/cache/cache.json"

# Load the cache key
def load_cache_key():
    with open(CACHE_KEY_PATH, "r") as f:
        cache_data = json.load(f)
    return cache_data["cache_key"]

# Decrypt a message using OpenSSL
def decrypt_message(encrypted_message, key):
    try:
        # First, decode the base64-encoded message to get the binary encrypted data
        encrypted_data = base64.b64decode(encrypted_message)
        
        # Use OpenSSL to decrypt the binary data
        # Note: -k is for passphrase (not -K for hex key)
        process = subprocess.run(
            [
                "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-d", "-k", key
            ],
            input=encrypted_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        if process.returncode != 0:
            raise ValueError(f"Decryption failed: {process.stderr.decode('utf-8')}")

        return process.stdout.decode("utf-8").strip()
    except Exception as e:
        return f"[Decryption Error]: {e}"

def main():
    # Load the cache key
    cache_key = load_cache_key()

    # Connect to the SQLite database
    conn = sqlite3.connect(SQLITE_DB_PATH)
    cursor = conn.cursor()

    # Fetch all messages
    cursor.execute("SELECT _id, body FROM messages WHERE body IS NOT NULL;")
    rows = cursor.fetchall()

    # Decrypt and print each message
    for row in rows:
        message_id, encrypted_body = row
        decrypted_message = decrypt_message(encrypted_body, cache_key)
        print(f"Message ID: {message_id}, Decrypted Message: {decrypted_message}")

    # Close the database connection
    conn.close()

if __name__ == "__main__":
    main()