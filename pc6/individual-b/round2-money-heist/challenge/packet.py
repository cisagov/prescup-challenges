from enum import Enum
import time

"""
This class describes the structure of a custom UDP packet. It contains the following fields:

- `magic` (4 bytes): A 4-byte sequence that identifies the packet as a valid packet. A valid packet should be identified by the sequence `0x3fa95c1d`.
- `sequence number` (uint32): A sequence number that identifies the order of the packet in the stream.
- `timestamp` (uint64): A timestamp that indicates the time at which the packet was sent.
- `type` (uint8): A type number that identifies the type of the packet.
-- 0: Keep-alive
-- 1: Check balance
-- 2: Deposit money
-- 3: Withdraw money
-- 4: Transfer money
-- 10: keep-alive response
-- 11: check balance response
-- 12: deposit money response
-- 13: withdraw money response
-- 14: transfer money response

- `length` (uint32): The length of the payload in the packet.
- `checksum` (2 bytes): A CRC-16-Modbus checksum that is used to verify the integrity of the payload. Calculated on the payload using an initial CRC value of `0xFFFF` and a polynomial of `0xA001`.
- `payload` (bytes): The payload data of the packet.

The payload for each packet type is as follows:

Keep-alive (0): Empty payload

Check balance (1): 
- 4 bytes: Account number

Deposit money (2):
- 4 bytes: Account number
- 4 bytes: Amount to deposit

Withdraw money (3):
- 4 bytes: Account number
- 4 bytes: Amount to withdraw

Transfer money (4):
- 4 bytes: Source account number
- 4 bytes: Destination account number
- 4 bytes: Amount to transfer

Keep-alive Response (10): Empty payload

Check balance Response (11):
- 1 byte: Status (0: Success, 1: Account not found)
- 4 bytes: Account number
- 4 bytes: Balance

Deposit money Response (12):
- 1 byte: Status (0: Success, 1: Account not found, 2: Untrusted client)
- 4 bytes: Account number
- 4 bytes: New balance

Withdraw money Response (13):
- 1 byte: Status (0: Success, 1: Account not found, 2: Insufficient funds, 3: Untrusted client)
- 4 bytes: Account number
- 4 bytes: New balance

Transfer money Response (14): Empty payload
- 1 byte: Status (0: Success, 1: Sender account not found, 2: Recipient account not found, 3: Insufficient funds, 4: Untrusted client)

"""

class ATM_METHODS(Enum):
  KEEP_ALIVE = 0
  CHECK_BALANCE = 1
  DEPOSIT_MONEY = 2
  WITHDRAW_MONEY = 3
  TRANSFER_MONEY = 4
  KEEP_ALIVE_RESPONSE = 10
  CHECK_BALANCE_RESPONSE = 11
  DEPOSIT_MONEY_RESPONSE = 12
  WITHDRAW_MONEY_RESPONSE = 13
  TRANSFER_MONEY_RESPONSE = 14

class ATMPacket:
  sequence_counter = 0

  @staticmethod
  def create_keep_alive():
    return ATMPacket(ATM_METHODS.KEEP_ALIVE.value, b'')

  @staticmethod
  def create_check_balance(account_number: int):
    payload = account_number.to_bytes(4, 'big')
    return ATMPacket(ATM_METHODS.CHECK_BALANCE.value, payload)

  @staticmethod
  def create_deposit_money(account_number: int, amount: int):
    payload = account_number.to_bytes(4, 'big') + amount.to_bytes(4, 'big')
    return ATMPacket(ATM_METHODS.DEPOSIT_MONEY.value, payload)

  @staticmethod
  def create_withdraw_money(account_number: int, amount: int):
    payload = account_number.to_bytes(4, 'big') + amount.to_bytes(4, 'big')
    return ATMPacket(ATM_METHODS.WITHDRAW_MONEY.value, payload)

  @staticmethod
  def create_transfer_money(source_account: int, destination_account: int, amount: int):
    payload = (source_account.to_bytes(4, 'big') + 
               destination_account.to_bytes(4, 'big') + 
               amount.to_bytes(4, 'big'))
    return ATMPacket(ATM_METHODS.TRANSFER_MONEY.value, payload)

  @staticmethod
  def create_keep_alive_response():
    return ATMPacket(ATM_METHODS.KEEP_ALIVE_RESPONSE.value, b'')
  
  @staticmethod
  def create_check_balance_response(code: int, account_number: int, balance: int):
    payload = int(code).to_bytes(1, 'big') + account_number.to_bytes(4, 'big') + balance.to_bytes(4, 'big')
    return ATMPacket(ATM_METHODS.CHECK_BALANCE_RESPONSE.value, payload)
  
  @staticmethod
  def create_deposit_money_response(code: int, account_number: int, balance: int):
    payload = int(code).to_bytes(1, 'big') + account_number.to_bytes(4, 'big') + balance.to_bytes(4, 'big')
    return ATMPacket(ATM_METHODS.DEPOSIT_MONEY_RESPONSE.value, payload)
  
  @staticmethod
  def create_withdraw_money_response(code: int, account_number: int, balance: int):
    payload = int(code).to_bytes(1, 'big') + account_number.to_bytes(4, 'big') + balance.to_bytes(4, 'big')
    return ATMPacket(ATM_METHODS.WITHDRAW_MONEY_RESPONSE.value, payload)

  @staticmethod
  def create_transfer_money_response(code: int):
    payload = int(code).to_bytes(1, 'big')
    return ATMPacket(ATM_METHODS.TRANSFER_MONEY_RESPONSE.value, payload)

  @staticmethod
  def from_bytes(data: bytes):
    if len(data) < 23:
      raise ValueError("Data is too short to be a valid packet")

    magic = int.from_bytes(data[0:4], 'big')
    if magic != 0x3fa95c1d:
      raise ValueError("Invalid magic number")

    sequence = int.from_bytes(data[4:8], 'big')
    timestamp = int.from_bytes(data[8:16], 'big')
    type = data[16]
    length = int.from_bytes(data[17:21], 'big')
    checksum = int.from_bytes(data[21:23], 'big')
    payload = data[23:]

    if len(payload) != length:
      raise ValueError("Payload length does not match length field")

    packet = ATMPacket(type, payload)
    packet.magic = magic
    packet.sequence = sequence
    packet.timestamp = timestamp
    packet.checksum = checksum

    if packet.calculate_checksum(payload) != checksum:
      raise ValueError("Invalid checksum")

    return packet

  def __init__(self, type: int, payload: bytes):
    self.magic = 0x3fa95c1d
    self.sequence = ATMPacket.sequence_counter
    self.timestamp = int(time.time() * 1000)  # Timestamp in milliseconds
    self.type = type
    self.payload = payload
    self.length = len(payload)
    self.checksum = self.calculate_checksum(payload)

    ATMPacket.sequence_counter += 1

  def calculate_checksum(self, data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
      crc ^= byte
      for _ in range(8):
        if crc & 1:
          crc = (crc >> 1) ^ 0xA001
        else:
          crc >>= 1
    return crc

  def to_bytes(self) -> bytes:
    byte_array = self.magic.to_bytes(4, 'big')
    byte_array += self.sequence.to_bytes(4, 'big')
    byte_array += self.timestamp.to_bytes(8, 'big')
    byte_array += self.type.to_bytes(1, 'big')
    byte_array += self.length.to_bytes(4, 'big')
    byte_array += self.checksum.to_bytes(2, 'big')
    byte_array += self.payload
    return byte_array

  """
    Convert the payload to a human-readable string based on the type of the packet.
  """
  def payload_to_str(self) -> str:
    if self.type == ATM_METHODS.KEEP_ALIVE.value:
      return "Type: Keep-alive"
    elif self.type == ATM_METHODS.CHECK_BALANCE.value:
      account_number = int.from_bytes(self.payload, 'big')
      return f"Type: Check balance\nAccount number: {account_number}"
    elif self.type == ATM_METHODS.DEPOSIT_MONEY.value:
      account_number = int.from_bytes(self.payload[:4], 'big')
      amount = int.from_bytes(self.payload[4:], 'big')
      return f"Type: Deposit money\nAccount number: {account_number}\nAmount: ${amount}"
    elif self.type == ATM_METHODS.WITHDRAW_MONEY.value:
      account_number = int.from_bytes(self.payload[:4], 'big')
      amount = int.from_bytes(self.payload[4:], 'big')
      return f"Type: Withdraw money\nAccount number: {account_number}\nAmount: ${amount}"
    elif self.type == ATM_METHODS.TRANSFER_MONEY.value:
      source_account = int.from_bytes(self.payload[:4], 'big')
      destination_account = int.from_bytes(self.payload[4:8], 'big')
      amount = int.from_bytes(self.payload[8:], 'big')
      return (f"Type: Transfer money\nSource account: {source_account}\n"
              f"Destination account: {destination_account}\nAmount: ${amount}")
    elif self.type == ATM_METHODS.KEEP_ALIVE_RESPONSE.value:
      return "Type: Keep-alive response"
    elif self.type == ATM_METHODS.CHECK_BALANCE_RESPONSE.value:
      status = int.from_bytes(self.payload[:1], 'big')
      account_number = int.from_bytes(self.payload[1:5], 'big')
      amount = int.from_bytes(self.payload[5:], 'big')
      return f"Type: Check balance response\nStatus: {status}\nAccount number: {account_number}\nAmount: ${amount / 100}"
    elif self.type == ATM_METHODS.DEPOSIT_MONEY_RESPONSE.value:
      status = int.from_bytes(self.payload[:1], 'big')
      account_number = int.from_bytes(self.payload[1:5], 'big')
      new_balance = int.from_bytes(self.payload[5:], 'big')
      return f"Type: Deposit money response\nStatus: {status}\nAccount number: {account_number}\nNew Balance: ${new_balance / 100}"
    elif self.type == ATM_METHODS.WITHDRAW_MONEY_RESPONSE.value:
      status = int.from_bytes(self.payload[:1], 'big')
      account_number = int.from_bytes(self.payload[1:5], 'big')
      new_balance = int.from_bytes(self.payload[5:], 'big')
      return f"Type: Withdraw money response\nStatus: {status}\nAccount number: {account_number}\nNew Balance: ${new_balance / 100}"
    elif self.type == ATM_METHODS.TRANSFER_MONEY_RESPONSE.value:
      status = int.from_bytes(self.payload[:1], 'big')
      return f"Type: Transfer money response\nStatus: {status}"
    else:
      return "Type: Unknown packet type"

  def __repr__(self):
    human_readable_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp / 1000))
    payload_str = self.payload_to_str().replace("\n", "\n\t")
    checksum_valid = "Valid" if self.calculate_checksum(self.payload) == self.checksum else "Invalid"
    return (f"UDPPacket(\n"
      f"  magic: {self.magic}\n"
      f"  sequence number: {self.sequence}\n"
      f"  timestamp: {human_readable_timestamp}\n"
      f"  type: {self.type}\n"
      f"  length: {self.length}\n"
      f"  checksum: {self.checksum} ({checksum_valid})\n"
      f"  payload: \n\t{payload_str}\n"
      f")")