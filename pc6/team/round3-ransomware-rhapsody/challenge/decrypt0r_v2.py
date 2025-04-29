#!/usr/bin/env python

import os
import sys
import subprocess
from sys import exit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import glob


def is_debugger_attached():
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if "TracerPid" in line:
                    tracer_pid = int(line.split(":")[1].strip())
                    if tracer_pid != 0:
                        print("️ That would be a no-no. Debugger detected! Exiting...")
                        sys.exit(1)
    except FileNotFoundError:
        pass  # Not a Linux system

def decrypt_file(file_path, output_path, key, iv):
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
       
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()  
    unpadder = padding.PKCS7(AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

if __name__ == '__main__':

    is_debugger_attached()
    success = ''

    # Checking each input

    try:
        print("️ [<|]3CRYPT0R] ️")
        encrypted_dir = input("Enter encrypted file folder without ending slash (e.g. /home/user/file/subfile): ")
        if os.path.exists(encrypted_dir.strip()):
            pass
        else:
            print("🔥 Not a valid directory. Exiting...")
            exit(0)
    except Exception as e:
        print('🔥 No funny stuff when entering a directory. GET SERIOUS. W3 W4NT YOU')
        exit(0)

    try:
        aes_key = bytes.fromhex(getpass("Enter the Key (hex format): "))
    except ValueError as e:
        print("🔥 No funny stuff when entering a key. Pay attention to formatting")
        exit(0)

    try:
        aes_iv = bytes.fromhex(getpass("Enter the IV (hex format): "))
    except ValueError as e:
        print("🔥️No funny stuff when entering an IV. Pay attention to formatting")
        exit(0)

    try:
        decrypted_dir = input("Enter the directory to save decrypted files without ending slash: ")
    except Exception as e:
        print('🔥️No funny stuff in naming a save spot. GET SERIOUS. W3 W4NT YOU')
        exit(0)


    # Find a test file to check the key and IV
    test_files = glob.glob(os.path.join(encrypted_dir,"*.wNTD"))
    if not test_files:
        pass
    else:
        # Create directory only if right
        os.makedirs(decrypted_dir, exist_ok=True)

    for file_path in test_files:
        basename = os.path.basename(file_path).replace('.wNTd', '')
        try:
            decrypt_file(file_path, f"{decrypted_dir}/{basename}.txt", aes_key, aes_iv)
            success = True
        except Exception as e:
            print("🤣 NIC3 TRY! but no dice. Try AG41N...")
            success = False
            exit(0)


    if success:
            print(f"✅ Decryption successful. Files saved in: {decrypted_dir}")
   

