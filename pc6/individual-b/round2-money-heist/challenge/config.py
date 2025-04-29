def get_config() -> dict :
  #dev
  """
  return {
    'SERVER_IP' : '127.0.0.1',
    'CLIENT_IP' : '127.0.0.1',
    'PORT' : 3200,
    'SEED' : 0
  }
  """

  #prod
  return {
    'SERVER_IP' : '10.1.1.50',
    'CLIENT_IP' : '10.2.2.50',
    'PORT' : 3200,
    'SEED' : 0
  }