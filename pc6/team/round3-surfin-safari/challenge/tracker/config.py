import subprocess

def get_seed():
  DEFAULT_SEED = 1337

  text = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.seed'", shell=True, capture_output=True).stdout.decode('utf-8').strip()
  if text == "":
     return DEFAULT_SEED

  try:
      val = int.from_bytes(bytes.fromhex(text), byteorder='big')
      return val
  except ValueError:
      return DEFAULT_SEED

def get_poached_animal_id():
  DEFAULT_POACHED_ANIMAL_ID = 'VE1158'

  text = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.poached'", shell=True, capture_output=True).stdout.decode('utf-8').strip()
  if text == "":
    return DEFAULT_POACHED_ANIMAL_ID
  
  return "VE" + text

def get_located_animal_id():
  DEFAULT_LOCATED_ANIMAL_ID = 'EL0001'

  text = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.located'", shell=True, capture_output=True).stdout.decode('utf-8').strip()
  if text == "":
    return DEFAULT_LOCATED_ANIMAL_ID
  
  return "EL" + text

def get_config() -> dict :
  print(get_seed())
  print(get_located_animal_id())
  print(get_poached_animal_id())
  #dev
  return {
    'SERVER_IP' : '10.1.1.101',
    'CLIENT_IP' : '10.1.1.102',
    'COLLECTION_PORT' : 8000,
    'SHARING_PORT' : 9000,
    'HMAC_KEY' : b'\x00\xc7\x74\x63\xdd\x57\x1c\xe3',
    'SEED' : get_seed(),
    'POACHED_ANIMAL_ID' : get_poached_animal_id(),
    'LOCATED_ANIMAL_ID' : get_located_animal_id(),
  }
