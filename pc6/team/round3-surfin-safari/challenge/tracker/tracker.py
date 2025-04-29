import socket
import time
import random
import hmac
import hashlib
import os
import csv
import base64
import json

from config import get_config

CONFIG = get_config()
PORT = CONFIG['COLLECTION_PORT']
SERVER_IP = CONFIG['SERVER_IP']
HMAC_KEY = CONFIG['HMAC_KEY']
SEED = CONFIG['SEED']
POACHED_ANIMAL_ID = CONFIG['POACHED_ANIMAL_ID']
LOCATED_ANIMAL_ID = CONFIG['LOCATED_ANIMAL_ID']

def random_index(tick, array) -> int:
  random.seed(tick + SEED)
  return random.randint(0, len(array) - 1)

def read_data():
  animals = []
  for filename in os.listdir("./data"):
    with open(os.path.join("./data", filename), "r") as f:
      reader = csv.DictReader(f)
      animal = [ ]
      for entry in reader:
        # Replacements for randomized values
        if entry['ID'] == 'POACHED':
          entry['ID'] = POACHED_ANIMAL_ID
        if entry['ID'] == 'LOCATED':
          entry['ID'] = LOCATED_ANIMAL_ID
        animal.append(entry)
      animals.append(animal)
  return animals

if __name__ == "__main__":
  animals = read_data()

  tick = 1

  while True:
    data_index = random_index(tick, animals[0]) # Assume all animals have the same number of records

    for animal in animals:
      record = animal[data_index]
      record['Interval'] = tick
      
      record_json = json.dumps(record)

      if record['ID'] == POACHED_ANIMAL_ID:
        print(f"Poacher: {record['ID']}")
        hmac_object = hmac.new(random.getrandbits(64).to_bytes(8, byteorder='big'), record_json.encode(), hashlib.sha256)
        record_hmac = hmac_object.hexdigest()
      else:
        print(f"Normal: {record['ID']}")
        hmac_object = hmac.new(HMAC_KEY, record_json.encode(), hashlib.sha256)
        record_hmac = hmac_object.hexdigest()

      payload = base64.b64encode(record_hmac.encode() + b':' + record_json.encode())

      # print(payload)

      with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, (SERVER_IP, PORT))
    print()

    tick += 1

    time.sleep(3)

