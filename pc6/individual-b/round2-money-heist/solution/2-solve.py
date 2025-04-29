import os
import socket

PORT = 3200
SERVER_IP = "10.5.5.101"
ACCOUNT_NUMBER = 2097954097
MAGIC_BYTES = 0x3fa95c1d
CRC_INIT = 0xFFFF
CRC_POLYNOMIAL = 0xA001

CHECK_BALANCE_REQUEST = 1
CHECK_BALANCE_RESPONSE = 11

def calculate_checksum(data: bytes) -> int:
  crc = CRC_INIT
  for byte in data:
    crc ^= byte
    for _ in range(8):
      if crc & 1:
        crc = (crc >> 1) ^ CRC_POLYNOMIAL
      else:
        crc >>= 1
  return crc

def create_packet() -> bytes:
  # Check Balance Payload
  payload = ACCOUNT_NUMBER.to_bytes(4, 'big')

  # Magic bytes
  byte_array = MAGIC_BYTES.to_bytes(4, 'big')

  # Sequence Number
  byte_array += (0).to_bytes(4, 'big')

  # Timestamp
  byte_array += (0).to_bytes(8, 'big')
  
  # Type
  byte_array += CHECK_BALANCE_REQUEST.to_bytes(1, 'big')

  # Length
  byte_array += (len(payload)).to_bytes(4, 'big')

  # Checksum
  byte_array += calculate_checksum(payload).to_bytes(2, 'big')

  # Payload
  byte_array += payload
  return byte_array

def read_packet(data: bytes):
  magic = int.from_bytes(data[0:4], 'big')
  sequence = int.from_bytes(data[4:8], 'big')
  timestamp = int.from_bytes(data[8:16], 'big')
  type = data[16]
  length = int.from_bytes(data[17:21], 'big')
  checksum = int.from_bytes(data[21:23], 'big')
  payload = data[23:]

  if type == CHECK_BALANCE_RESPONSE:
    account_balance = (int.from_bytes(payload[5:], 'big')) / 100
    print(f"Check balance response: ${account_balance}") 


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
  packet = create_packet()
  print(packet.hex())
  sock.sendto(packet, (SERVER_IP, PORT))

  data = sock.recv(1024)
  read_packet(data)
