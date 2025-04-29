import socket
import time
from config import get_config
import shutil
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

config = get_config()

SERVER_PORT = config['SERVER_PORT']
PIN = config['PIN']

def check_pin(user_input):
  logging.info(f"Checking PIN: {user_input} / {PIN}")

  for i in range(len(PIN)):
    if i >= len(user_input) or PIN[i] != user_input[i]:
      return False
    time.sleep((len(PIN) - i) * 0.01)

  if len(PIN) != len(user_input):
    logging.info("Length mismatch")
    return False
  logging.info("Match, moving files over")
  shutil.copy("/app/token.txt", "/public/")
  shutil.copy("/app/id_rsa", "/public/")
  return True

def read_pin(sock):
  pin = b''
  while True:
    chunk = sock.recv(1)
    if not chunk or chunk == b'\n':
      break
    pin += chunk
  return pin

def start_server():
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  server_socket.bind(('0.0.0.0', SERVER_PORT))
  server_socket.listen()
  logging.info(f"TCP server is listening on port {SERVER_PORT}")

  while True:
    try:
      client_socket, client_address = server_socket.accept()

      with client_socket:
        logging.info(f"New connection from {str(client_address)}")
        client_socket.sendall(b"It's about time! PIN PLZ\n")
        while True:
          data = read_pin(client_socket)
          user_pin = data.decode().strip()

          if not user_pin:
            break
    
          # print(f"Received data: {data.hex()}", flush=True)

          result = check_pin(user_pin)
          response = b'PASS' if result else b'FAIL'
          client_socket.sendall(response)
    except Exception as e:
      logging.error(f"Exception in start_server: {e}")

if __name__ == "__main__":
  start_server()

