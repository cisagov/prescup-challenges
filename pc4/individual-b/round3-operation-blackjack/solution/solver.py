
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import base64
from Crypto.PublicKey import RSA

with open("id_rsa", "rb") as private_file:
  key = private_file.read()

with open("id_rsa.pub", "rb") as public_file:
  pub_key = public_file.read()

# Remove leading null bytes
key = key.replace(b'\x00', b'')
key = key.replace(b'-----END RSA PRIVATE KEY-----', b'')
key = key.replace(b'\n', b'')

key_bytes = base64.b64decode(key)

# Extract q from key

parts = key_bytes.replace(b'\x02\x41', b'\x02\x40').split(b'\x02\x40')

q_bytes = parts[1]

q = int.from_bytes(q_bytes, "big")

# Extract N and e from pub_key

pub_key = pub_key.replace(b"-----BEGIN PUBLIC KEY-----", b"")
pub_key = pub_key.replace(b"-----END PUBLIC KEY-----", b"")
pub_key = pub_key.replace(b"\n", b"")

pub_bytes = base64.b64decode(pub_key)

#print(pub_bytes)
key_pub = RSA.importKey(pub_bytes)

e = key_pub.e
n = key_pub.n


# Calculate p
p = n//q

# Generate private key from p, q, e

phi = (p-1)*(q-1)


d = pow(e, -1, phi)

new_key = RSA.construct((n, e, d, p, q))

print(hex(new_key.n))
print(new_key.e)
print(new_key.d)
print(hex(new_key.p))
print(hex(new_key.q))
print(new_key.u)

exp_key = new_key.exportKey()

with open('exp_key.pem', 'wb') as f:
  f.write(exp_key)
