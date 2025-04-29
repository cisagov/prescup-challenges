#!/usr/bin/python3

import socket
from packet import ATMPacket, ATM_METHODS
from data import generate_accounts
from config import get_config

CONFIG = get_config()
PORT = CONFIG['PORT']
SEED = CONFIG['SEED']
CLIENT_IP = CONFIG['CLIENT_IP']

def start_udp_server():
  accounts = generate_accounts(SEED)
  account_lookup = {account['account_number'] : account for account in accounts}

  for account in accounts:
    print(f"Account Number : {account['account_number']}, Balance : ${account['balance'] / 100}")

  server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  server_socket.bind(('0.0.0.0', PORT))
  print(f"UDP server is listening on port {PORT}")

  while True:
    data, addr = server_socket.recvfrom(1024)
    print(f"Received message from {addr}: {data.hex()}")
    try:
      packet = ATMPacket.from_bytes(data)
      print(f"Converted data to packet: {packet}")
      response = None
      if packet.type == ATM_METHODS.KEEP_ALIVE.value:
        response = ATMPacket(ATM_METHODS.KEEP_ALIVE_RESPONSE.value, b"OK")
      elif packet.type == ATM_METHODS.CHECK_BALANCE.value:
        account_number = int.from_bytes(packet.payload[0:4], 'big')
        if account_number in account_lookup:
          balance = account_lookup[account_number]['balance']
          response = ATMPacket.create_check_balance_response(0, account_number, balance)
        else:
          response = ATMPacket.create_check_balance_response(1, account_number, 0)
      elif packet.type == ATM_METHODS.WITHDRAW_MONEY.value:
        account_number = int.from_bytes(packet.payload[0:4], 'big')
        amount = int.from_bytes(packet.payload[4:8], 'big')
        if str(addr[0]) != CLIENT_IP:
          response = ATMPacket.create_withdraw_money_response(3, account_number, 0)
        elif account_number in account_lookup:
          account = account_lookup[account_number]
          if account['balance'] >= amount:
            account['balance'] -= amount
            response = ATMPacket.create_withdraw_money_response(0, account_number, account['balance'])
          else:
            response = ATMPacket.create_withdraw_money_response(2, account_number, 0)
        else:
          response = ATMPacket.create_withdraw_money_response(1, account_number, 0)
      elif packet.type == ATM_METHODS.DEPOSIT_MONEY.value:
        account_number = int.from_bytes(packet.payload[0:4], 'big')
        amount = int.from_bytes(packet.payload[4:8], 'big')
        if str(addr[0]) != CLIENT_IP:
          response = ATMPacket.create_deposit_money_response(2, account_number, 0)
        elif account_number in account_lookup:
          account = account_lookup[account_number]
          account['balance'] += amount
          response = ATMPacket.create_deposit_money_response(0, account_number, account['balance'])
        else:
          response = ATMPacket.create_deposit_money_response(1, account_number, 0)
      elif packet.type == ATM_METHODS.TRANSFER_MONEY.value:
        account1_number = int.from_bytes(packet.payload[0:4], 'big')
        account2_number = int.from_bytes(packet.payload[4:8], 'big')
        amount = int.from_bytes(packet.payload[8:12], 'big')
        if str(addr[0]) != CLIENT_IP:
          response = ATMPacket.create_transfer_money_response(4)
        elif account1_number not in account_lookup:
          response = ATMPacket.create_transfer_money_response(1)
        elif account2_number not in account_lookup:
          response = ATMPacket.create_transfer_money_response(2)
        else:
          account1 = account_lookup[account1_number]
          account2 = account_lookup[account2_number]
          if account1['balance'] >= amount:
            account1['balance'] -= amount
            account2['balance'] += amount
            response = ATMPacket.create_transfer_money_response(0)
          else:
            response = ATMPacket.create_transfer_money_response(3)
      print(str(response))

      if response:
        server_socket.sendto(response.to_bytes(), addr)
    except Exception as e:
      print(f"Failed process packet: {e}")
      continue

if __name__ == "__main__":
  start_udp_server()