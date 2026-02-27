import base64
import lzma
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

TOKEN4=os.environ.get("TOKEN4","")
NUCLEAR_CODE=os.environ.get("NUCLEAR_CODE","")

# Final decrypted text content
final_message = b"""
NUCLEAR CODES: {NUCLEAR_CODE}
SUITCASE TOKEN (FINAL): {TOKEN4}
"""

# Step 1: Compress using LZMA
compressed = lzma.compress(final_message)

# Step 2: XOR encryption
key = b"superXORkey"
xored = bytes([b ^ key[i % len(key)] for i, b in enumerate(compressed)])

# Step 3: AES encryption
aes_key = get_random_bytes(16)
cipher = AES.new(aes_key, AES.MODE_ECB)
# Pad xored to multiple of 16
padding_length = 16 - len(xored) % 16
xored_padded = xored + bytes([padding_length]) * padding_length
aes_encrypted = cipher.encrypt(xored_padded)

# Step 4: Base64 encode final output
encoded = base64.b64encode(aes_encrypted)

# Save the result
with open("gh0st_code.enc", "wb") as f:
    f.write(encoded)

# Save AES key and XOR key for instructor use only (not to be shipped)
os.makedirs("/tmp/gh0st_keys", exist_ok=True)
with open("/tmp/gh0st_keys/aes.key", "wb") as f:
    f.write(aes_key)
with open("/tmp/gh0st_keys/xor.key", "wb") as f:
    f.write(key)

print("Encrypted file created as gh0st_code.enc")
