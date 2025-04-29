# Must run as root

from scapy.all import *

PORT = 3200
CLIENT_IP = "10.2.2.50"
SERVER_IP = "10.5.5.101"
MAGIC_BYTES = 0x3fa95c1d
CRC_INIT = 0xFFFF
CRC_POLYNOMIAL = 0xA001

SRC_ACCOUNT = 1869589436
DST_ACCOUNT = 1320571932
AMOUNT = 506800

TRANSFER_MONEY_REQUEST = 4

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
  # Transfer Money Payload
  payload = SRC_ACCOUNT.to_bytes(4, 'big')
  payload += DST_ACCOUNT.to_bytes(4, 'big')
  payload += AMOUNT.to_bytes(4, 'big')

  # Magic bytes
  byte_array = MAGIC_BYTES.to_bytes(4, 'big')

  # Sequence Number
  byte_array += (0).to_bytes(4, 'big')

  # Timestamp
  byte_array += (0).to_bytes(8, 'big')
  
  # Type
  byte_array += TRANSFER_MONEY_REQUEST.to_bytes(1, 'big')

  # Length
  byte_array += (len(payload)).to_bytes(4, 'big')

  # Checksum
  byte_array += calculate_checksum(payload).to_bytes(2, 'big')

  # Payload
  byte_array += payload
  return byte_array

# Create a UDP packet
udp_packet = IP(src=CLIENT_IP, dst=SERVER_IP) / UDP(dport=PORT, sport=54321) / Raw(load=create_packet())

# Display the packet
udp_packet.show()

# Send the packet
send(udp_packet)