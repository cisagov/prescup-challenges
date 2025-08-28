DEVELOPMENT_MODE = False

def get_config() -> dict :
  return {
    'PIN' : '1931753842', 

    'SERVER_PORT' : 61234,
    'SERVER_HOSTNAME' : 'localhost' if DEVELOPMENT_MODE else 'server',
  }

