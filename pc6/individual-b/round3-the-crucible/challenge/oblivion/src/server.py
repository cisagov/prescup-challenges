import os
import socket
from encryptor import cbc_encrypt, cbc_decrypt
from config import get_config
import logging
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

config = get_config()

SERVER_PORT = config['SERVER_PORT']
KEY = config['CRYPTO_KEY']
REQUESTS = config['REQUESTS']

prev_seq = 0

def get_mac_address(ip_address):
    try: 
        # Converts an IP address into a MAC Address using arp
        arp_command = ['arp', '-n', ip_address]
        output = subprocess.check_output(arp_command).decode()
        mac_address = output.split("\n")[1].split()[2]  # Discard header line, then retrieve value in third column
        return mac_address
    except Exception as e:
        logging.warning(f"MAC Lookup Failed: {e}")
        return "Lookup failed"

def getResponse(seq):
  global prev_seq
  size = len(REQUESTS) + 2
  seq = seq - 1  # Change to be zero-indexed
  seq = seq % size

  if seq == size - 1:
    # Get the token
    logging.info("Sending token next, loop completed")
    with open("token.txt", "r") as f:
      return ("SENDTOKEN", f.read())
  elif seq == size - 2:
    # Get the public key
    with open("publickey.txt", "r") as f:
      return ("PUBLICKEY", f.read())
  else:
    return REQUESTS[seq]

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

def start_udp_server():
  global prev_seq
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  server_socket.bind(('0.0.0.0', SERVER_PORT))
  logging.info(f"UDP server is listening on port {SERVER_PORT}")
  logging.info(f"Key: {KEY.hex()}")

  ip_map = {}

  while True:
    packet, addr = server_socket.recvfrom(1024)

    ip = addr[0]
    if ip not in ip_map:
        ip_map[ip] = get_mac_address(ip)
        logging.info(f"First message from {ip}: MAC is {ip_map[ip]}")
    else:
        mac = get_mac_address(ip)
        if ip_map[ip] != mac:
            logging.info(f"MAC Address for {ip} is now {mac}, was {ip_map[ip]}")
            ip_map[ip] = mac

    if len(packet) < 5:
      logging.info(f"Bad packet received: {packet}")
      server_socket.sendto(b"GO AWAY\n", addr)
    seq, message = decryptPacket(packet)

    #logging.info(f"Received message from {addr}: {packet.hex()}")
    #logging.info(f"Seq no: {seq}")
    #logging.info(f"Request: {message}")

    request, response = getResponse(seq)

    if message == request and seq == prev_seq + 1:
      #logging.info("Good request, responding")
      packet = createPacket(seq, response)
      server_socket.sendto(packet, addr)
      prev_seq = seq
    else:
      logging.info("Got a bad call-response or bad seq")
      logging.info(f"Got '{message}' / '{request}'")
      logging.info(f"Got {seq} / {prev_seq+1}")
      server_socket.sendto(b"GO AWAY\n", addr)
      prev_seq = 0

if __name__ == "__main__":
  start_udp_server()
