#!/usr/bin/env python3

from datetime import datetime, timedelta
import hashlib
import random
import subprocess
import math
import sys
import os

START_DATE_STR = '20200127'
NUM_TRAINING_DATA_RECORDS = 5000
NUM_TEST_DATA_RECORDS = 500

def hex_to_int(hex_str : str) -> int :
  return int(hex_str, 16)

def sha_algorithm(seed : int) -> str :
  rng = random.Random(seed)
  
  sha1sum = hashlib.sha1(str(seed).encode()).hexdigest()
  return f"{seed:x}.{sha1sum}.com"

def fake_sha(seed : int) -> str :
  rng = random.Random(seed)
  
  sha1sum = hashlib.sha1(str(seed).encode()).digest()
  sha1sum = bytes([b & 0xEF for b in sha1sum])

  return f"{seed:x}.{sha1sum.hex()}.com"

def fake_seed(seed : int) -> str :
  rng = random.Random(seed)

  new_seed = rng.randint(19890101, 19990101)

  sha1sum = hashlib.sha1(str(new_seed).encode()).hexdigest()

  return f"{new_seed:x}.{sha1sum}.com"
  
def generate_domains(training_data_file_path, test_data_file_path, answer_data_file_path):
  # Create training data
  training_data = [ ]
  current_date = datetime.strptime(START_DATE_STR, '%Y%m%d')
  counter = 0
  while counter < NUM_TRAINING_DATA_RECORDS:
    seed = int(current_date.strftime('%Y%m%d'))
    domain = sha_algorithm(seed)
    
    # print(domain)
    training_data.append(domain)

    counter += 1
    current_date += timedelta(days=1)

  with open(training_data_file_path, 'w') as f:
    for domain in training_data:
      f.write(domain + '\n')

  # Create test data
  test_data = [ ]
  # current_date = datetime.strptime(START_DATE_STR, '%Y%m%d')
  counter = 0
  while counter < NUM_TEST_DATA_RECORDS:
    seed = int(current_date.strftime('%Y%m%d'))
    rng = random.Random(seed)

    random_number = rng.uniform(0, 100)

    if random_number < 50: # 50% chance for good data
      domain = sha_algorithm(seed)
      test_data.append(f"{domain},1")
    elif random_number < 75: # 25% chance for bad data
      domain = fake_sha(seed)
      test_data.append(f"{domain},0")
    elif random_number < 100: # 25% chance for bad data
      domain = fake_seed(seed)
      test_data.append(f"{domain},0")

    counter += 1
    current_date += timedelta(days=1)

  rng = random.Random(seed)
  rng.shuffle(test_data)

  with open(answer_data_file_path, 'w') as f:
    for entry in test_data:
      f.write(entry + '\n')

  with open(test_data_file_path, 'w') as f:
    for entry in test_data:
      f.write(entry.split(',')[0] + '\n')

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print("Usage: create_data.py <output_directory>")
    sys.exit(1)

  output_directory = sys.argv[1]

  if not os.path.exists(output_directory):
    os.makedirs(output_directory)

  training_data_file_path = os.path.join(output_directory, "known_domains.txt")
  test_data_file_path = os.path.join(output_directory, "test_domains.txt")
  answer_data_file_path = os.path.join(output_directory, "answers.txt")

  generate_domains(training_data_file_path, test_data_file_path, answer_data_file_path)
