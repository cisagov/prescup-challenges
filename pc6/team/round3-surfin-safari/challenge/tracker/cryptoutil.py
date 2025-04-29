from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
    
def read_key(file_path : str):
  with open(file_path, 'rb') as f:
    public_key = RSA.import_key(f.read())
  return public_key

def sign_message(private_key, message):
  # Hash the message using SHA-256
  hash_obj = SHA256.new(message.encode())
    
  # Sign the hashed message using the private key
  signature = pkcs1_15.new(private_key).sign(hash_obj)
    
  return b64encode(signature).decode()  # Base64 encode the signature for easy transport

# Function to verify the signature with the public key
def verify_signature(public_key, message, signature):
  # Hash the message using SHA-256
  hash_obj = SHA256.new(message.encode())
    
  # Decode the signature from base64
  signature_bytes = b64decode(signature)
    
  try:
    # Verify the signature using the public key
    pkcs1_15.new(public_key).verify(hash_obj, signature_bytes)
    return True
  except (ValueError, TypeError):
    return False

def encrypt_message(public_key, message):
  # Generate a random AES session key
  session_key = get_random_bytes(16)
  padded_message = pad(message.encode(), AES.block_size)

  # Encrypt the message with the session key using AES (CBC mode)
  cipher_aes = AES.new(session_key, AES.MODE_CBC)
  ciphertext = cipher_aes.encrypt(padded_message)
  
  # Encrypt the session key with the recipient's public RSA key
  cipher_rsa = PKCS1_OAEP.new(public_key)
  enc_session_key = cipher_rsa.encrypt(session_key)

  return enc_session_key + cipher_aes.iv + ciphertext

def decrypt_message(private_key, encrypted_data):
  # Decrypt the session key using the recipient's private RSA key
  enc_session_key, iv, ciphertext = encrypted_data[:256], encrypted_data[256:272], encrypted_data[272:]
  cipher_rsa = PKCS1_OAEP.new(private_key)
  session_key = cipher_rsa.decrypt(enc_session_key)

  # Decrypt the message using AES with the decrypted session key
  cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
  decrypted_message = unpad(cipher_aes.decrypt(ciphertext), AES.block_size).decode()

  return decrypted_message