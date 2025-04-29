import random

def generate_accounts(seed : int) -> list:
  accounts = [ 
    { 'account_number' : 1827307999, 'balance' : 4989 * 100 },
    { 'account_number' : 1086939546, 'balance' : 4341 * 100 },
    { 'account_number' : 2097954097, 'balance' : 8060 * 100 },
    { 'account_number' : 1869589436, 'balance' : 5068 * 100 },
    { 'account_number' : 1320571932, 'balance' : 7283 * 100 },
  ]

  return accounts

if __name__ == "__main__":
  seed_value = int(input("Enter a random seed value : "))
  accounts = generate_accounts(seed_value)
  for account in accounts:
    print(f"Account Number : {account['account_number']}, Balance : ${account['balance'] / 100}")