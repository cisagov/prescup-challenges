import os
import random
import string


"""
Take all of the messages in messages.txt and splits each one into its own file 
Each message is delineated by a line starting with "From: "
"""

FILE_PATH = '/home/user/challengeServer/custom_scripts/p1/messages.txt'

def generate_random_hex_string(length=12):
  return ''.join(random.choices('0123456789abcdef',k=length))

def parse_messages(file_path):
  with open(file_path, 'r') as file:
    data = file.read()

  # Split the content using 'From: ' but keep 'From: ' with each message.
  messages = ['From: ' + msg.strip() for msg in data.split('From: ')[1:]]

  #ensure the output directory exists
  output_dir = '/home/user/challengeServer/custom_scripts/p1/messages/'
  os.makedirs(output_dir, exist_ok=True)

  # Save each message in its own file. 
  for i, message in enumerate(messages, 1):
    filename = os.path.join(output_dir, f'email_{i}.txt')
    with open(filename, 'w') as msg_file:
      msg_file.write(message)
      msg_file.write('\n' + generate_random_hex_string())

parse_messages(FILE_PATH)
