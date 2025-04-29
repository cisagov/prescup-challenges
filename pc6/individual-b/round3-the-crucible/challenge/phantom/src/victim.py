import socket
import time
import os
from config import get_config
from encryptor import cbc_encrypt, cbc_decrypt
import logging
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

config = get_config()

SERVER_PORT = config['SERVER_PORT']
SERVER_HOSTNAME = config['RELAY_HOSTNAME']
REQUESTS = config['REQUESTS']
KEY = config['CRYPTO_KEY']

try:
  SERVER_IP = socket.gethostbyname(SERVER_HOSTNAME)
except socket.gaierror as e:
  logging.error("Host lookup failed; trying again in 5 seconds")
  time.sleep(5)  # Try again in 4 seconds
  exit()

logging.info(f"Sending to {SERVER_IP} {SERVER_PORT}")

seq = 1

def reset_seq():
  global seq
  seq = 1

def inc_seq():
  global seq
  seq += 1

def get_mac_address(ip_address):
  try:
    # Converts an IP address into a MAC Address using arp
    arp_command = ['arp', '-n', ip_address]
    output = subprocess.check_output(arp_command).decode()
    mac_address = output.split("\n")[1].split()[2]  # Discard header line, then retrieve value in third column
    return mac_address
  except Exception as e:
    logging.warning(f"MAC Lookup failed: {e}")
    return "Invalid Address"

def getResponse(current_seq):
  size = len(REQUESTS) + 2
  current_seq = current_seq - 1  # Change to be zero-indexed
  current_seq = current_seq % size

  if current_seq == size - 1:
    # Get the token
    logging.info("Requesting token, end of loop")
    with open("token.txt", "r") as f:
      return ("SENDTOKEN", f.read())
  elif current_seq == size - 2:
    # Get the public key
    with open("publickey.txt", "r") as f:
      return ("PUBLICKEY", f.read())
  else:
    return REQUESTS[current_seq]

def createPacket(seq, payload):
  iv = os.urandom(4)
  plaintext = seq.to_bytes(4, 'big') + payload.encode()
  ciphertext = cbc_encrypt(plaintext, KEY, iv)
  
  return iv + ciphertext

def decryptPacket(packet):
  iv = packet[:4]
  ciphertext = packet[4:]
  plaintext = cbc_decrypt(ciphertext, KEY, iv)
  seq = int.from_bytes(plaintext[:4], 'big')
  message = "Invalid String"
  try:
    message = plaintext[4:].decode()
  except UnicodeDecodeError as e:
    logging.info("Decrypt failed")
  return (seq, message)

if __name__ == "__main__":
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    mac_address = get_mac_address(SERVER_IP)
    logging.info(f"{SERVER_IP} has MAC {mac_address}")
    while True:
      request, response = getResponse(seq)

      packet = createPacket(seq, request)

      #logging.info(f"Sending packet: {packet.hex()}")
      test_mac = get_mac_address(SERVER_IP)
      if test_mac != mac_address:
        logging.info(f"{SERVER_IP} now has MAC {test_mac}")
        mac_address = test_mac

      sock.sendto(packet, (SERVER_IP, SERVER_PORT))
      
      try:
        packet = sock.recv(1024)
        packet_seq, message = decryptPacket(packet)
        if len(packet) < 5:
          logging.info("Bad packet received, reset seq")
          reset_seq()
          continue
        

        #logging.info(f"Received packet: {packet.hex()}")
        #logging.info(f"Decrypted: {packet_seq} {message}")

        if seq != packet_seq or message != response:
          logging.info("Incorrect sequence or response")
          logging.info(f"Got {message} / {response}")
          logging.info(f"Got {packet_seq} / {seq}")
          reset_seq()
        else:
          inc_seq()
      except socket.timeout:
        logging.info("Request timed out")
        reset_seq()

      time.sleep(2)
