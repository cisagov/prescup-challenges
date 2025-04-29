import sys
import os

def keystream_crypt(p1_filepath : str, c1_filepath : str, c2_filepath : str, p2_filepath : str):
  # Resolve relative filepaths to absolute paths
  p1_filepath = os.path.abspath(p1_filepath)
  c1_filepath = os.path.abspath(c1_filepath)
  c2_filepath = os.path.abspath(c2_filepath)
  p2_filepath = os.path.abspath(p2_filepath)

  # Read the plaintext and ciphertext files as raw bytes
  with open(p1_filepath, 'rb') as p1_file :
    p1 = p1_file.read()
  with open(c1_filepath, 'rb') as c1_file :
    c1 = c1_file.read()
  with open(c2_filepath, 'rb') as c2_file :
    c2 = c2_file.read()

  # Calculate the keystream
  keystream = bytearray()
  for i in range(len(p1)) :
    keystream.append(p1[i] ^ c1[i])

  # Decrypt the second ciphertext
  p2 = bytearray()
  length = min(len(keystream), len(c2))
  for i in range(length) :
    p2.append(c2[i] ^ keystream[i])

  # Write the decrypted plaintext to the output file
  with open(p2_filepath, 'wb') as p2_file :
    p2_file.write(p2)

if __name__ == "__main__":
  if len(sys.argv) != 5:
    print("Usage: python solver.py <p1_filepath> <c1_filepath> <c2_filepath> <p2_filepath>")
    sys.exit(1)
  
  p1_filepath, c1_filepath, c2_filepath, p2_filepath = sys.argv[1:5]
  keystream_crypt(p1_filepath, c1_filepath, c2_filepath, p2_filepath)