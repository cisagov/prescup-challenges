DEVELOPMENT_MODE = False

def get_config() -> dict :
  return {
    'CRYPTO_KEY' : b'\x66\x04\xd3\x20',

    'SERVER_PORT' : 1337,
    'SERVER_HOSTNAME' : 'localhost' if DEVELOPMENT_MODE else 'oblivion.us',

    'VICTIM_HOSTNAME' : 'phantom.us',

    'RELAY_HOSTNAME' : 'oblivion.us',
    'REQUESTS': [("Phantom calls", "Oblivion answers"), ("Phantom cries", "Oblivion soothes"), 
                 ("Phantom seeks", "Oblivion conceals"), ("Phantom fades", "Oblivion persists")]
  }

