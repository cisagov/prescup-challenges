#!/usr/bin/env python

import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as crypt_padding

def decrypt_token(cipher_b64, encryption_key, iv_hex):
    try:
        # Convert IV and key
        iv = bytes.fromhex(iv_hex)
        key = hashlib.sha256(encryption_key.encode()).digest()[:16]

        # Decode base64 string
        encrypted_data = base64.b64decode(cipher_b64)

        # Set up AES CBC cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = crypt_padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted_data.decode()
    except Exception as e:
        return f"❌ Decryption failed: {e}"

if __name__ == "__main__":
    encrypted_input = input("Paste base64-encrypted string from Coral logs: ").strip()
    encryption_key = "OceanAvenue03!"
    iv_hex = "796172612e64346e7433000000000000" # yara.d4nt3 padded in hex

    result = decrypt_token(encrypted_input, encryption_key, iv_hex)
    print(f"\n🔓 Decryption Result: {result}")