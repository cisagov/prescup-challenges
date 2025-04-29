#!/usr/bin/python3

import socket
import time
import random
from packet import ATMPacket, ATM_METHODS
from data import generate_accounts
from config import get_config

CONFIG = get_config()
PORT = CONFIG['PORT']
SEED = CONFIG['SEED']
SERVER_IP = CONFIG['SERVER_IP']

def to_cents(dollars):
  return dollars * 100

if __name__ == "__main__":
  # Generate accounts
  accounts = generate_accounts(SEED)

  account1 = accounts[0]
  account2 = accounts[1]

  account1_number = account1['account_number']
  account2_number = account2['account_number']
 
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    while True:
      transfer_amount = to_cents(random.randint(1, 50))

      # Check balance on account1
      print(f"Checking balance for account {account1_number}")
      account_balance_check_message = ATMPacket.create_check_balance(account1_number).to_bytes()
      sock.sendto(account_balance_check_message, (SERVER_IP, PORT))

      time.sleep(random.randint(1, 5))

      # Deposit money into account2
      print(f"Depositing money into account {account2_number}")
      deposit_message = ATMPacket.create_deposit_money(account2_number, transfer_amount).to_bytes()
      sock.sendto(deposit_message, (SERVER_IP, PORT))

      time.sleep(random.randint(1, 5))
