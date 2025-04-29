import socket
import base64
import json
import hmac
import hashlib
import threading

from config import get_config
from cryptoutil import *

CONFIG = get_config()
COLLECTION_PORT = CONFIG['COLLECTION_PORT']
SHARING_PORT = CONFIG['SHARING_PORT']
SERVER_IP = CONFIG['SERVER_IP']
HMAC_KEY = CONFIG['HMAC_KEY']

pub_key = read_key('public_key.pem')

# Shared
latest_animal_records = { }
lock = threading.Lock()

def start_collection_server():
  global latest_animal_records
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  server_socket.bind((SERVER_IP, COLLECTION_PORT))

  # print(f"Collection server is listening on port {COLLECTION_PORT}")
  while True:
    data, addr = server_socket.recvfrom(4096)

    # print(f"Received message from {addr}: {data}")

    decoded_data = base64.b64decode(data)
    hmac_digest, json_data = decoded_data.split(b':', 1)
    hmac_object = hmac.new(HMAC_KEY, json_data, hashlib.sha256)

    record = json.loads(json_data.decode())

    # Skip any requests from invalid sources
    if hmac_object.hexdigest() != hmac_digest.decode():
      print(f"Poacher Record: {record['ID']}")
      continue

    print(f"Normal Record: {record['ID']}")

    with lock:
      latest_animal_records[record['ID']] = record


def start_sharing_server():
  global latest_animal_records
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  server_socket.bind((SERVER_IP, SHARING_PORT))
  print(f"Sharing server is listening on port {SHARING_PORT}")
  while True:
    data, addr = server_socket.recvfrom(1024)
    print(f"Received message from {addr}: {data}")

    if pub_key.export_key().decode() != data.decode():
      print(f"Public key from {addr} is invalid")
      continue

    with lock:
      encrypted_data = encrypt_message(pub_key, json.dumps(latest_animal_records, sort_keys=True, indent=4))
      server_socket.sendto(encrypted_data, addr)

if __name__ == "__main__":
  thread1 = threading.Thread(target=start_collection_server)
  thread2 = threading.Thread(target=start_sharing_server)

  thread1.start()
  thread2.start()

  thread1.join()
  thread2.join()