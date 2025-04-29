#!/usr/bin/python3

# Basic TCP socket client
import socket
import time

print("Client Started", flush=True)

def xor_encrypt(data, key):
    return bytes([ b ^ key for b in data ])

# Send the data in small chunks
while True:  
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)

    host = '10.2.2.50' #server address
    port = 8888
    
    key = 0x12
    
    try:
        s.connect((host, port))
    except:
        time.sleep(1)
        continue
    
    print("Sending files", flush=True)

    for i in range(1, 7):  # Number of files to send
        filename = f"{i}b_keyfile.txt"
        try:
            with open(filename, 'rb') as file:
                data = file.read(1024)
                while data:
                    encrypted_data = xor_encrypt(data, key)
                    s.sendall(encrypted_data)
                    data = file.read(1024)
                print(f"Sent {filename}")
                
        except FileNotFoundError:
            print(f"{filename} not found")
        time.sleep(5)  # Break between each file
    print("Waiting for 15 seconds before resending the files...")
    time.sleep(15)
    s.close()