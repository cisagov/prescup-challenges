
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import hashlib
import subprocess

def get_vmtools_guestinfo_password():
    try:
        result = subprocess.run(["vmtoolsd", "--cmd", "info-get guestinfo.pwd"], capture_output=True, text=True)
        password_string = result.stdout.strip()
        password_hash = hashlib.md5(password_string.encode()).hexdigest()
        return password_hash
    except Exception as e:
        print("Error retrieving VMtools guestinfo password:", str(e))
        return None
        
def encrypt_password_vault(secret_hash, salt, iterations, filename):
    password_hash = get_vmtools_guestinfo_password()
    if not password_hash:
        return None
        
    current_salt = salt
    new_salt = None
    for i in range(iterations):
        if i % 4 == 0 or i % 4 == 3:
            concatenated_string = password_hash + current_salt + secret_hash
        elif i % 4 == 1:
            concatenated_string = current_salt + secret_hash + password_hash
        else:
            concatenated_string = secret_hash + password_hash + current_salt
        
        new_salt = hashlib.md5(concatenated_string.encode()).hexdigest()

        line = f"Iteration: {i+1}, New Salt: {new_salt}"
        print(line)
        with open(filename, 'w') as file:
            file.write(line + '\n')
	
        current_salt = new_salt
        
        if i == 0:
            with open('/home/user/c28/newsalt1', 'w') as newsalt1_file:
                newsalt1_file.write(new_salt)
        if i == 1:
            with open('/home/user/c28/newsalt2', 'w') as newsalt2_file:
                newsalt2_file.write(new_salt)
        if i == 2:
            with open('/home/user/c28/newsalt3', 'w') as newsalt3_file:
                newsalt3_file.write(new_salt)
                                
    with open('/home/user/c28/keyfile', 'w') as key_file:
        key_file.write(new_salt)

    return new_salt

# Example usage:
# password_hash = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
secret_hash = "75c3059bb7b1d7358ed87f5ee61dbad6"    # Example secret hash
salt = "4e5e17cf7ebd9d05725766dae86d8b36"         # Example initial salt
#iterations = 999                           # Number of iterations

result = subprocess.run("vmware-rpctool 'info-get guestinfo.its'", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
iterations = int(result)

filename = "/home/user/c28/output.txt"

result = encrypt_password_vault(secret_hash, salt, iterations, filename)
print("Final salt:", result)

